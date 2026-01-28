# End-to-End Test Scenarios Specification

**Version:** 1.0.0
**Date:** 2026-01-28
**Status:** Complete
**Classification:** Testing Documentation
**Author:** QA & DevOps Engineer

---

## Table of Contents

1. [Overview](#1-overview)
2. [E2E Test Approach](#2-e2e-test-approach)
3. [Test Environment Configuration](#3-test-environment-configuration)
4. [Test Data Management](#4-test-data-management)
5. [E2E Test Scenarios](#5-e2e-test-scenarios)
6. [CI/CD Integration](#6-cicd-integration)
7. [Performance Benchmarks](#7-performance-benchmarks)
8. [Appendix](#appendix)

---

## 1. Overview

### 1.1 Purpose

This document defines comprehensive end-to-end (E2E) test scenarios for the XRPL Agent Wallet MCP server. E2E tests validate complete user workflows and system integration against real XRPL testnet infrastructure.

### 1.2 Scope

E2E tests cover:
- Complete wallet lifecycle operations
- Policy enforcement across all tiers (1-3)
- Multi-signature workflows
- Key rotation and recovery
- Error recovery and resilience
- Real XRPL testnet transactions

### 1.3 Out of Scope

- Unit test coverage (see test-patterns-unit.md)
- Integration test coverage (separate document)
- Performance stress testing (separate test plan)
- Security penetration testing (security team)

### 1.4 Terminology

| Term | Definition |
|------|------------|
| **Testnet** | XRPL test network for development (wss://s.altnet.rippletest.net:51233) |
| **Faucet** | Service providing free testnet XRP (https://faucet.altnet.rippletest.net) |
| **E2E Scenario** | Complete workflow testing real system interactions |
| **Given/When/Then** | BDD-style scenario structure |
| **Cleanup** | Teardown operations ensuring test isolation |

---

## 2. E2E Test Approach

### 2.1 Testing Philosophy

```
┌─────────────────────────────────────────────────────────────────────┐
│                    E2E Testing Principles                            │
├─────────────────────────────────────────────────────────────────────┤
│  1. Test against REAL XRPL testnet (not mocks)                      │
│  2. Test complete user workflows end-to-end                         │
│  3. Verify XRPL ledger state after operations                       │
│  4. Test with realistic data and timing                             │
│  5. Ensure complete cleanup after each test                         │
│  6. Parallel execution with isolated test accounts                  │
└─────────────────────────────────────────────────────────────────────┘
```

### 2.2 E2E Test Stack

```typescript
/**
 * E2E Test Technology Stack
 */
const e2eStack = {
  // Test framework
  framework: 'Vitest',

  // XRPL connectivity
  network: 'wss://s.altnet.rippletest.net:51233',
  faucet: 'https://faucet.altnet.rippletest.net',

  // MCP testing
  mcpClient: '@modelcontextprotocol/sdk',

  // Assertions
  assertions: 'Vitest expect + custom matchers',

  // Test data
  dataFactory: 'Custom E2ETestDataFactory',

  // Reporting
  reporter: 'vitest-reporter-json + HTML',
};
```

### 2.3 Test Categories

| Category | Description | Execution Time | Frequency |
|----------|-------------|----------------|-----------|
| **Smoke** | Critical path validation | < 2 min | Every commit |
| **Core** | Full workflow coverage | < 15 min | Every PR |
| **Extended** | Edge cases, recovery | < 45 min | Nightly |
| **Performance** | Benchmark validation | < 30 min | Weekly |

### 2.4 Scenario Structure

All E2E scenarios follow this standard structure:

```gherkin
Feature: [Feature Name]
  As a [role]
  I want to [action]
  So that [benefit]

  Background:
    Given [shared preconditions]

  Scenario: [Scenario Name]
    Given [preconditions]
    When [action]
    Then [expected outcome]
    And [additional assertions]

    Cleanup:
      [teardown steps]
```

---

## 3. Test Environment Configuration

### 3.1 Testnet Configuration

```typescript
// e2e/config/testnet.config.ts

export const testnetConfig = {
  // XRPL Testnet endpoints (with failover)
  endpoints: [
    'wss://s.altnet.rippletest.net:51233',
    'wss://s.devnet.rippletest.net:51233',
  ],

  // Faucet for funding test accounts
  faucet: {
    url: 'https://faucet.altnet.rippletest.net/accounts',
    retryAttempts: 3,
    retryDelayMs: 5000,
    fundingAmount: 1000, // XRP
  },

  // Network timeouts
  timeouts: {
    connectionMs: 30000,
    transactionMs: 60000,
    ledgerCloseMs: 5000,
  },

  // Reserve requirements
  reserves: {
    baseReserve: 10,      // XRP
    ownerReserve: 2,      // XRP per owned object
  },
};
```

### 3.2 MCP Server Test Configuration

```typescript
// e2e/config/mcp-server.config.ts

export const mcpServerConfig = {
  // Server startup
  serverCommand: 'node',
  serverArgs: ['dist/index.js'],

  // Data directory (isolated per test run)
  dataDir: '/tmp/xrpl-wallet-mcp-e2e-{testRunId}',

  // Logging
  logLevel: 'debug',
  logFile: '/tmp/xrpl-wallet-mcp-e2e-{testRunId}/server.log',

  // Encryption
  testPassword: 'E2E-Test-Password-Secure-2026!',

  // Policy defaults for testing
  defaultPolicy: {
    max_amount_per_transaction_drops: '1000000000', // 1000 XRP
    daily_limit_drops: '10000000000',               // 10000 XRP
    allowed_destinations: ['*'],                     // Allow all for testing
    max_transactions_per_day: 100,
    allow_token_transactions: true,
  },
};
```

### 3.3 Test Isolation Strategy

```typescript
// e2e/helpers/test-isolation.ts

/**
 * Ensure complete test isolation.
 * Each test gets:
 * - Unique test run ID
 * - Fresh data directory
 * - New testnet accounts (funded via faucet)
 * - Isolated MCP server instance
 */
export class TestIsolation {
  private testRunId: string;
  private dataDir: string;
  private accounts: Map<string, TestAccount>;

  async setup(): Promise<void> {
    // Generate unique test run ID
    this.testRunId = `e2e-${Date.now()}-${randomBytes(4).toString('hex')}`;

    // Create isolated data directory
    this.dataDir = `/tmp/xrpl-wallet-mcp-e2e-${this.testRunId}`;
    await fs.mkdir(this.dataDir, { recursive: true });

    // Initialize account pool
    this.accounts = new Map();
  }

  async teardown(): Promise<void> {
    // Close all XRPL connections
    for (const account of this.accounts.values()) {
      await account.cleanup();
    }

    // Remove test data directory
    await fs.rm(this.dataDir, { recursive: true, force: true });
  }

  async getTestAccount(name: string): Promise<TestAccount> {
    if (!this.accounts.has(name)) {
      const account = await TestAccount.createAndFund(name);
      this.accounts.set(name, account);
    }
    return this.accounts.get(name)!;
  }
}
```

---

## 4. Test Data Management

### 4.1 Testnet Account Preparation

```typescript
// e2e/helpers/test-account.ts

/**
 * Manages testnet accounts for E2E testing.
 */
export class TestAccount {
  public address: string;
  public seed: string;
  public wallet: Wallet;

  private constructor(wallet: Wallet) {
    this.wallet = wallet;
    this.address = wallet.classicAddress;
    this.seed = wallet.seed!;
  }

  /**
   * Create and fund a new testnet account.
   */
  static async createAndFund(name: string): Promise<TestAccount> {
    // Generate new wallet
    const wallet = Wallet.generate();

    // Fund via faucet
    await retryWithBackoff(async () => {
      const response = await fetch(testnetConfig.faucet.url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ destination: wallet.classicAddress }),
      });

      if (!response.ok) {
        throw new Error(`Faucet funding failed: ${response.status}`);
      }

      return response.json();
    }, {
      maxAttempts: testnetConfig.faucet.retryAttempts,
      delayMs: testnetConfig.faucet.retryDelayMs,
    });

    // Wait for funding to appear on ledger
    await waitForAccountActivation(wallet.classicAddress);

    return new TestAccount(wallet);
  }

  /**
   * Get current XRP balance from ledger.
   */
  async getBalance(): Promise<string> {
    const client = await getXrplClient();
    const response = await client.request({
      command: 'account_info',
      account: this.address,
    });
    return response.result.account_data.Balance;
  }

  /**
   * Cleanup: return funds to faucet if possible.
   */
  async cleanup(): Promise<void> {
    try {
      const balance = await this.getBalance();
      const balanceXrp = parseFloat(dropsToXrp(balance));

      // Return remaining funds to faucet (keep reserve)
      if (balanceXrp > 15) {
        const returnAmount = balanceXrp - 12; // Keep base reserve + buffer
        // Send back to faucet return address if available
        console.log(`Test account ${this.address}: ${returnAmount} XRP remaining`);
      }
    } catch (error) {
      // Account may be deleted, ignore
    }
  }
}
```

### 4.2 Test Data Factory

```typescript
// e2e/helpers/test-data-factory.ts

/**
 * Factory for generating test data.
 */
export class E2ETestDataFactory {
  /**
   * Generate test transaction amounts for different tiers.
   */
  static getTestAmounts() {
    return {
      // Tier 1: Autonomous (< 100 XRP)
      tier1Small: '1000000',      // 1 XRP in drops
      tier1Medium: '50000000',    // 50 XRP in drops
      tier1Max: '99000000',       // 99 XRP in drops

      // Tier 2: Confirmation required (100-1000 XRP)
      tier2Min: '100000000',      // 100 XRP in drops
      tier2Medium: '500000000',   // 500 XRP in drops
      tier2Max: '999000000',      // 999 XRP in drops

      // Tier 3: Multi-sign required (> 1000 XRP)
      tier3Min: '1000000000',     // 1000 XRP in drops
      tier3Large: '5000000000',   // 5000 XRP in drops
    };
  }

  /**
   * Generate test wallet configurations.
   */
  static getWalletConfig(tier: 1 | 2 | 3) {
    const configs = {
      1: {
        name: 'e2e-tier1-wallet',
        policy: {
          max_amount_per_transaction_drops: '100000000',
          daily_limit_drops: '1000000000',
          require_confirmation_above_drops: '100000000',
          require_cosign_above_drops: '1000000000',
        },
      },
      2: {
        name: 'e2e-tier2-wallet',
        policy: {
          max_amount_per_transaction_drops: '1000000000',
          daily_limit_drops: '10000000000',
          require_confirmation_above_drops: '100000000',
          require_cosign_above_drops: '1000000000',
        },
      },
      3: {
        name: 'e2e-tier3-wallet',
        policy: {
          max_amount_per_transaction_drops: '10000000000',
          daily_limit_drops: '100000000000',
          require_confirmation_above_drops: '100000000',
          require_cosign_above_drops: '1000000000',
        },
      },
    };
    return configs[tier];
  }

  /**
   * Generate SignerList configuration for multi-sign tests.
   */
  static getSignerListConfig(
    agentAddress: string,
    humanAddresses: string[]
  ): SignerListConfig {
    return {
      signers: [
        { address: agentAddress, weight: 1, role: 'agent' },
        ...humanAddresses.map((addr, i) => ({
          address: addr,
          weight: 1,
          role: 'human_approver' as const,
          name: `Human Approver ${i + 1}`,
        })),
      ],
      quorum: 2, // Agent + 1 human
      timeout_seconds: 300, // 5 minutes for E2E tests
    };
  }
}
```

### 4.3 XRPL Ledger Assertions

```typescript
// e2e/helpers/xrpl-assertions.ts

/**
 * Custom assertions for XRPL ledger state verification.
 */
export const xrplAssertions = {
  /**
   * Assert transaction exists on ledger with expected result.
   */
  async assertTransactionOnLedger(
    txHash: string,
    expectedResult: string = 'tesSUCCESS'
  ): Promise<void> {
    const client = await getXrplClient();

    const response = await client.request({
      command: 'tx',
      transaction: txHash,
    });

    expect(response.result.validated).toBe(true);
    expect(response.result.meta?.TransactionResult).toBe(expectedResult);
  },

  /**
   * Assert account balance matches expected value.
   */
  async assertBalance(
    address: string,
    expectedDrops: string,
    toleranceDrops: string = '100000' // 0.1 XRP tolerance for fees
  ): Promise<void> {
    const client = await getXrplClient();

    const response = await client.request({
      command: 'account_info',
      account: address,
    });

    const actualBalance = BigInt(response.result.account_data.Balance);
    const expected = BigInt(expectedDrops);
    const tolerance = BigInt(toleranceDrops);

    expect(actualBalance).toBeGreaterThanOrEqual(expected - tolerance);
    expect(actualBalance).toBeLessThanOrEqual(expected + tolerance);
  },

  /**
   * Assert SignerList configured on account.
   */
  async assertSignerListConfigured(
    address: string,
    expectedQuorum: number
  ): Promise<void> {
    const client = await getXrplClient();

    const response = await client.request({
      command: 'account_objects',
      account: address,
      type: 'signer_list',
    });

    const signerList = response.result.account_objects.find(
      obj => obj.LedgerEntryType === 'SignerList'
    );

    expect(signerList).toBeDefined();
    expect(signerList!.SignerQuorum).toBe(expectedQuorum);
  },

  /**
   * Assert account has been deleted from ledger.
   */
  async assertAccountDeleted(address: string): Promise<void> {
    const client = await getXrplClient();

    await expect(
      client.request({
        command: 'account_info',
        account: address,
      })
    ).rejects.toThrow(/actNotFound/);
  },

  /**
   * Assert regular key is set on account.
   */
  async assertRegularKeySet(
    address: string,
    expectedRegularKey: string
  ): Promise<void> {
    const client = await getXrplClient();

    const response = await client.request({
      command: 'account_info',
      account: address,
    });

    expect(response.result.account_data.RegularKey).toBe(expectedRegularKey);
  },
};
```

---

## 5. E2E Test Scenarios

### Scenario E2E-001: Complete Wallet Lifecycle

```gherkin
Feature: Complete Wallet Lifecycle
  As an AI agent
  I want to manage the complete lifecycle of a wallet
  So that I can create, use, and properly decommission wallets

Background:
  Given a running MCP server connected to XRPL testnet
  And a funded testnet account for the destination

Scenario: Create, fund, transact, rotate keys, and delete wallet
  # Preconditions
  Given no wallet exists with name "lifecycle-test-wallet"
  And I have a test password "LifecycleTest2026!"

  # Step 1: Create wallet
  When I call wallet_create with:
    | parameter | value |
    | name | lifecycle-test-wallet |
    | network | testnet |
  Then the response should contain:
    | field | pattern |
    | wallet_id | ^[a-f0-9-]{36}$ |
    | address | ^r[1-9A-HJ-NP-Za-km-z]{24,34}$ |
    | status | created |
  And the wallet should be listed in wallet_list response

  # Step 2: Fund wallet via faucet
  When I fund the wallet via testnet faucet
  Then after waiting for ledger close
  And the wallet_get_balance response should show >= 100 XRP

  # Step 3: Tier 1 transaction (autonomous)
  When I call wallet_sign with:
    | parameter | value |
    | wallet_address | {wallet_address} |
    | unsigned_tx | {payment_10_xrp} |
  Then the response should have status "approved"
  And the transaction should be signed
  When I submit the signed transaction
  Then the transaction should appear on ledger with "tesSUCCESS"
  And destination balance should increase by ~10 XRP

  # Step 4: Key rotation
  When I call wallet_rotate with:
    | parameter | value |
    | wallet_id | {wallet_id} |
    | reason | Scheduled rotation |
  Then the response should have status "completed"
  And the response should contain new_address (different from original)
  And the old key should no longer sign transactions
  And the new key should successfully sign transactions

  # Step 5: Delete wallet
  When I call wallet_delete with:
    | parameter | value |
    | wallet_id | {wallet_id} |
    | confirm_delete | true |
  Then the response should have status "deleted"
  And the wallet should not be listed in wallet_list response
  And keystore file should be removed from disk

Cleanup:
  - Delete test wallet if still exists
  - Close XRPL client connection
  - Remove test data directory

Expected Duration: 3-5 minutes
```

**Implementation:**

```typescript
// e2e/scenarios/wallet-lifecycle.e2e.test.ts

describe('E2E-001: Complete Wallet Lifecycle', () => {
  let isolation: TestIsolation;
  let mcpClient: McpClient;
  let destinationAccount: TestAccount;
  let createdWalletId: string;
  let createdWalletAddress: string;

  beforeAll(async () => {
    isolation = new TestIsolation();
    await isolation.setup();

    mcpClient = await McpClient.connect();
    destinationAccount = await isolation.getTestAccount('destination');
  }, 120000); // 2 minute timeout for setup

  afterAll(async () => {
    // Cleanup created wallet if test failed mid-way
    if (createdWalletId) {
      try {
        await mcpClient.call('wallet_delete', {
          wallet_id: createdWalletId,
          confirm_delete: true,
        });
      } catch (e) {
        // Ignore - wallet may already be deleted
      }
    }

    await mcpClient.close();
    await isolation.teardown();
  });

  test('Step 1: Create wallet', async () => {
    const result = await mcpClient.call('wallet_create', {
      name: 'lifecycle-test-wallet',
      network: 'testnet',
    });

    expect(result.wallet_id).toMatch(/^[a-f0-9-]{36}$/);
    expect(result.address).toMatch(/^r[1-9A-HJ-NP-Za-km-z]{24,34}$/);
    expect(result.status).toBe('created');

    createdWalletId = result.wallet_id;
    createdWalletAddress = result.address;

    // Verify in wallet_list
    const listResult = await mcpClient.call('wallet_list', {});
    const wallet = listResult.wallets.find(w => w.wallet_id === createdWalletId);
    expect(wallet).toBeDefined();
  });

  test('Step 2: Fund wallet via faucet', async () => {
    // Fund via testnet faucet
    await fundViaFaucet(createdWalletAddress);

    // Wait for ledger close
    await waitForLedgerClose();

    // Check balance
    const balanceResult = await mcpClient.call('wallet_get_balance', {
      wallet_address: createdWalletAddress,
    });

    const balanceXrp = parseFloat(dropsToXrp(balanceResult.balance_drops));
    expect(balanceXrp).toBeGreaterThanOrEqual(100);
  }, 60000);

  test('Step 3: Tier 1 transaction (autonomous)', async () => {
    // Build payment transaction
    const payment = await buildPaymentTransaction(
      createdWalletAddress,
      destinationAccount.address,
      '10000000' // 10 XRP
    );

    // Sign via wallet_sign
    const signResult = await mcpClient.call('wallet_sign', {
      wallet_address: createdWalletAddress,
      unsigned_tx: payment.unsigned_blob,
    });

    expect(signResult.status).toBe('approved');
    expect(signResult.signed_tx).toBeDefined();

    // Submit to XRPL
    const submitResult = await submitTransaction(signResult.signed_tx);

    // Verify on ledger
    await xrplAssertions.assertTransactionOnLedger(
      submitResult.tx_hash,
      'tesSUCCESS'
    );

    // Verify destination balance
    const destBalance = await destinationAccount.getBalance();
    // Balance should have increased by ~10 XRP
    expect(BigInt(destBalance)).toBeGreaterThan(
      BigInt(await destinationAccount.getBalance()) + BigInt('9000000')
    );
  }, 60000);

  test('Step 4: Key rotation', async () => {
    const originalAddress = createdWalletAddress;

    // Rotate keys
    const rotateResult = await mcpClient.call('wallet_rotate', {
      wallet_id: createdWalletId,
      reason: 'Scheduled rotation',
    });

    expect(rotateResult.status).toBe('completed');
    expect(rotateResult.new_address).toBeDefined();
    expect(rotateResult.new_address).not.toBe(originalAddress);

    // Verify old key cannot sign
    const payment = await buildPaymentTransaction(
      originalAddress,
      destinationAccount.address,
      '1000000' // 1 XRP
    );

    // New wallet address should be able to sign
    createdWalletAddress = rotateResult.new_address;

    // Verify new key can sign
    const signResult = await mcpClient.call('wallet_sign', {
      wallet_address: createdWalletAddress,
      unsigned_tx: payment.unsigned_blob,
    });

    expect(signResult.status).toBe('approved');
  }, 90000);

  test('Step 5: Delete wallet', async () => {
    const deleteResult = await mcpClient.call('wallet_delete', {
      wallet_id: createdWalletId,
      confirm_delete: true,
    });

    expect(deleteResult.status).toBe('deleted');

    // Verify not in wallet_list
    const listResult = await mcpClient.call('wallet_list', {});
    const wallet = listResult.wallets.find(w => w.wallet_id === createdWalletId);
    expect(wallet).toBeUndefined();

    // Verify keystore file removed
    const keystorePath = path.join(
      isolation.dataDir,
      'wallets',
      `${createdWalletId}.json`
    );
    await expect(fs.access(keystorePath)).rejects.toThrow();

    createdWalletId = null; // Prevent cleanup from trying to delete again
  });
});
```

---

### Scenario E2E-002: Tier 1 Policy Enforcement (Autonomous)

```gherkin
Feature: Tier 1 Policy Enforcement
  As an AI agent
  I want Tier 1 transactions to be automatically approved
  So that low-value operations proceed without delay

Background:
  Given a running MCP server with default policy
  And a funded wallet with Tier 1 policy limits

Scenario: Autonomous approval for transactions below threshold
  # Preconditions
  Given wallet "tier1-wallet" with:
    | setting | value |
    | max_amount_per_transaction_drops | 100000000 |
    | require_confirmation_above_drops | 100000000 |
  And the wallet has balance of 500 XRP
  And destination address "rDestination123..."

  # Test boundary: just under threshold
  When I request signing for 99 XRP to destination
  Then the response should have:
    | field | value |
    | status | approved |
    | policy_tier | 1 |
    | requires_confirmation | false |
  And the signed transaction should be valid

  # Test minimum valid amount
  When I request signing for 0.000001 XRP (1 drop)
  Then the response should have status "approved"

  # Test multiple Tier 1 transactions (within daily limit)
  When I request signing for 10 XRP to destination (transaction 2)
  Then the response should have status "approved"
  When I request signing for 10 XRP to destination (transaction 3)
  Then the response should have status "approved"

  # Verify all transactions on ledger
  Then all 3 transactions should appear on ledger with "tesSUCCESS"

Cleanup:
  - Delete test wallet
  - Close connections

Expected Duration: 2-3 minutes
```

**Implementation:**

```typescript
// e2e/scenarios/tier1-policy.e2e.test.ts

describe('E2E-002: Tier 1 Policy Enforcement', () => {
  let isolation: TestIsolation;
  let mcpClient: McpClient;
  let testWallet: { id: string; address: string };
  let destinationAccount: TestAccount;
  const signedTransactions: string[] = [];

  beforeAll(async () => {
    isolation = new TestIsolation();
    await isolation.setup();

    mcpClient = await McpClient.connect();
    destinationAccount = await isolation.getTestAccount('destination');

    // Create and fund test wallet
    const createResult = await mcpClient.call('wallet_create', {
      name: 'tier1-policy-test',
      network: 'testnet',
      policy: {
        max_amount_per_transaction_drops: '100000000',  // 100 XRP
        require_confirmation_above_drops: '100000000',   // 100 XRP
        require_cosign_above_drops: '1000000000',        // 1000 XRP
        daily_limit_drops: '500000000',                  // 500 XRP
      },
    });

    testWallet = { id: createResult.wallet_id, address: createResult.address };

    // Fund wallet
    await fundViaFaucet(testWallet.address);
    await waitForLedgerClose();
  }, 120000);

  afterAll(async () => {
    if (testWallet?.id) {
      await mcpClient.call('wallet_delete', {
        wallet_id: testWallet.id,
        confirm_delete: true,
      }).catch(() => {});
    }
    await mcpClient.close();
    await isolation.teardown();
  });

  test('Just under threshold (99 XRP) - autonomous approval', async () => {
    const payment = await buildPaymentTransaction(
      testWallet.address,
      destinationAccount.address,
      '99000000' // 99 XRP
    );

    const result = await mcpClient.call('wallet_sign', {
      wallet_address: testWallet.address,
      unsigned_tx: payment.unsigned_blob,
    });

    expect(result.status).toBe('approved');
    expect(result.policy_tier).toBe(1);
    expect(result.requires_confirmation).toBe(false);
    expect(result.signed_tx).toBeDefined();

    signedTransactions.push(result.signed_tx);
  });

  test('Minimum amount (1 drop) - autonomous approval', async () => {
    const payment = await buildPaymentTransaction(
      testWallet.address,
      destinationAccount.address,
      '1' // 1 drop
    );

    const result = await mcpClient.call('wallet_sign', {
      wallet_address: testWallet.address,
      unsigned_tx: payment.unsigned_blob,
    });

    expect(result.status).toBe('approved');
    expect(result.policy_tier).toBe(1);

    signedTransactions.push(result.signed_tx);
  });

  test('Multiple Tier 1 transactions within daily limit', async () => {
    for (let i = 0; i < 3; i++) {
      const payment = await buildPaymentTransaction(
        testWallet.address,
        destinationAccount.address,
        '10000000' // 10 XRP each
      );

      const result = await mcpClient.call('wallet_sign', {
        wallet_address: testWallet.address,
        unsigned_tx: payment.unsigned_blob,
      });

      expect(result.status).toBe('approved');
      signedTransactions.push(result.signed_tx);
    }
  });

  test('Verify all transactions on ledger', async () => {
    for (const signedTx of signedTransactions) {
      const submitResult = await submitTransaction(signedTx);
      await xrplAssertions.assertTransactionOnLedger(
        submitResult.tx_hash,
        'tesSUCCESS'
      );
    }
  }, 120000);
});
```

---

### Scenario E2E-003: Tier 2 Policy Enforcement (Confirmation Required)

```gherkin
Feature: Tier 2 Policy Enforcement
  As an AI agent
  I want Tier 2 transactions to require confirmation
  So that medium-value operations have human oversight

Background:
  Given a running MCP server with tiered policy
  And a funded wallet with Tier 2 threshold at 100 XRP

Scenario: Confirmation required for transactions at or above threshold
  # Preconditions
  Given wallet "tier2-wallet" with:
    | setting | value |
    | require_confirmation_above_drops | 100000000 |
    | require_cosign_above_drops | 1000000000 |
  And the wallet has balance of 1000 XRP

  # Test exactly at threshold
  When I request signing for 100 XRP to destination
  Then the response should have:
    | field | value |
    | status | pending_confirmation |
    | policy_tier | 2 |
    | requires_confirmation | true |
    | approval_id | {uuid} |

  # Confirm the transaction
  When I confirm the pending transaction with approval_id
  Then the response should have status "approved"
  And the signed transaction should be valid

  # Test above threshold
  When I request signing for 500 XRP to destination
  Then the response should have:
    | field | value |
    | status | pending_confirmation |
    | policy_tier | 2 |

  # Test confirmation timeout
  When I wait 60 seconds without confirming
  Then the pending transaction should expire
  And status query should return "expired"

  # Test rejection
  When I request signing for 200 XRP to destination
  And I reject the pending transaction
  Then the response should have status "rejected"
  And the transaction should not be signed

Cleanup:
  - Delete test wallet
  - Close connections

Expected Duration: 3-4 minutes
```

**Implementation:**

```typescript
// e2e/scenarios/tier2-policy.e2e.test.ts

describe('E2E-003: Tier 2 Policy Enforcement', () => {
  let isolation: TestIsolation;
  let mcpClient: McpClient;
  let testWallet: { id: string; address: string };
  let destinationAccount: TestAccount;

  beforeAll(async () => {
    isolation = new TestIsolation();
    await isolation.setup();

    mcpClient = await McpClient.connect();
    destinationAccount = await isolation.getTestAccount('destination');

    // Create wallet with Tier 2 policy
    const createResult = await mcpClient.call('wallet_create', {
      name: 'tier2-policy-test',
      network: 'testnet',
      policy: {
        max_amount_per_transaction_drops: '1000000000',  // 1000 XRP
        require_confirmation_above_drops: '100000000',   // 100 XRP
        require_cosign_above_drops: '1000000000',        // 1000 XRP
        confirmation_timeout_seconds: 30,                 // Short timeout for testing
      },
    });

    testWallet = { id: createResult.wallet_id, address: createResult.address };
    await fundViaFaucet(testWallet.address);
    await waitForLedgerClose();
  }, 120000);

  afterAll(async () => {
    if (testWallet?.id) {
      await mcpClient.call('wallet_delete', {
        wallet_id: testWallet.id,
        confirm_delete: true,
      }).catch(() => {});
    }
    await mcpClient.close();
    await isolation.teardown();
  });

  test('Exactly at threshold (100 XRP) - requires confirmation', async () => {
    const payment = await buildPaymentTransaction(
      testWallet.address,
      destinationAccount.address,
      '100000000' // 100 XRP
    );

    const result = await mcpClient.call('wallet_sign', {
      wallet_address: testWallet.address,
      unsigned_tx: payment.unsigned_blob,
    });

    expect(result.status).toBe('pending_confirmation');
    expect(result.policy_tier).toBe(2);
    expect(result.requires_confirmation).toBe(true);
    expect(result.approval_id).toMatch(/^[a-f0-9-]{36}$/);

    // Confirm the transaction
    const confirmResult = await mcpClient.call('wallet_sign_confirm', {
      approval_id: result.approval_id,
      confirmed: true,
    });

    expect(confirmResult.status).toBe('approved');
    expect(confirmResult.signed_tx).toBeDefined();

    // Verify on ledger
    const submitResult = await submitTransaction(confirmResult.signed_tx);
    await xrplAssertions.assertTransactionOnLedger(submitResult.tx_hash);
  }, 90000);

  test('Above threshold (500 XRP) - requires confirmation', async () => {
    const payment = await buildPaymentTransaction(
      testWallet.address,
      destinationAccount.address,
      '500000000' // 500 XRP
    );

    const result = await mcpClient.call('wallet_sign', {
      wallet_address: testWallet.address,
      unsigned_tx: payment.unsigned_blob,
    });

    expect(result.status).toBe('pending_confirmation');
    expect(result.policy_tier).toBe(2);
    expect(result.approval_id).toBeDefined();

    // Confirm
    const confirmResult = await mcpClient.call('wallet_sign_confirm', {
      approval_id: result.approval_id,
      confirmed: true,
    });

    expect(confirmResult.status).toBe('approved');
  }, 60000);

  test('Confirmation timeout - transaction expires', async () => {
    const payment = await buildPaymentTransaction(
      testWallet.address,
      destinationAccount.address,
      '200000000' // 200 XRP
    );

    const result = await mcpClient.call('wallet_sign', {
      wallet_address: testWallet.address,
      unsigned_tx: payment.unsigned_blob,
    });

    expect(result.status).toBe('pending_confirmation');

    // Wait for timeout (30 seconds + buffer)
    await sleep(35000);

    // Try to confirm - should fail
    await expect(
      mcpClient.call('wallet_sign_confirm', {
        approval_id: result.approval_id,
        confirmed: true,
      })
    ).rejects.toThrow(/expired/i);

    // Check status
    const statusResult = await mcpClient.call('wallet_sign_status', {
      approval_id: result.approval_id,
    });

    expect(statusResult.status).toBe('expired');
  }, 60000);

  test('Rejection - transaction not signed', async () => {
    const payment = await buildPaymentTransaction(
      testWallet.address,
      destinationAccount.address,
      '150000000' // 150 XRP
    );

    const result = await mcpClient.call('wallet_sign', {
      wallet_address: testWallet.address,
      unsigned_tx: payment.unsigned_blob,
    });

    expect(result.status).toBe('pending_confirmation');

    // Reject the transaction
    const rejectResult = await mcpClient.call('wallet_sign_confirm', {
      approval_id: result.approval_id,
      confirmed: false,
      rejection_reason: 'Test rejection',
    });

    expect(rejectResult.status).toBe('rejected');
    expect(rejectResult.signed_tx).toBeUndefined();

    // Verify status
    const statusResult = await mcpClient.call('wallet_sign_status', {
      approval_id: result.approval_id,
    });

    expect(statusResult.status).toBe('rejected');
    expect(statusResult.rejection_reason).toBe('Test rejection');
  });
});
```

---

### Scenario E2E-004: Tier 3 Multi-Signature Workflow

```gherkin
Feature: Tier 3 Multi-Signature Workflow
  As an AI agent
  I want Tier 3 transactions to require multiple signatures
  So that high-value operations have maximum security

Background:
  Given a running MCP server with multi-sign configuration
  And a funded wallet with SignerList configured
  And two human approver accounts

Scenario: Complete multi-signature workflow for high-value transaction
  # Preconditions
  Given wallet "tier3-wallet" with SignerList:
    | signer | weight | role |
    | agent | 1 | agent |
    | human1 | 1 | human_approver |
    | human2 | 1 | human_approver |
  And SignerQuorum is 2 (agent + 1 human)
  And the wallet has balance of 5000 XRP

  # Initiate Tier 3 transaction
  When I request signing for 1500 XRP to destination
  Then the response should have:
    | field | value |
    | status | pending_approval |
    | policy_tier | 3 |
    | requires_cosign | true |
    | approval_id | {uuid} |
    | quorum.required | 2 |
    | quorum.collected | 0 |
  And human approvers should be notified

  # Human 1 signs
  When human1 signs the pending transaction
  Then the quorum status should be:
    | field | value |
    | collected | 1 |
    | met | false |

  # Agent completes multi-sign
  When agent calls wallet_sign_complete with approval_id
  Then the response should have status "completed"
  And the multi-signed transaction should contain 2 signatures
  And the transaction should appear on ledger with "tesSUCCESS"
  And the destination balance should increase by ~1500 XRP

Cleanup:
  - Delete test wallet (requires multi-sign)
  - Close all connections

Expected Duration: 5-7 minutes
```

**Implementation:**

```typescript
// e2e/scenarios/tier3-multisign.e2e.test.ts

describe('E2E-004: Tier 3 Multi-Signature Workflow', () => {
  let isolation: TestIsolation;
  let mcpClient: McpClient;
  let xrplClient: Client;

  let agentWallet: { id: string; address: string };
  let human1Account: TestAccount;
  let human2Account: TestAccount;
  let destinationAccount: TestAccount;

  beforeAll(async () => {
    isolation = new TestIsolation();
    await isolation.setup();

    mcpClient = await McpClient.connect();
    xrplClient = await getXrplClient();

    // Create human approver accounts
    human1Account = await isolation.getTestAccount('human1');
    human2Account = await isolation.getTestAccount('human2');
    destinationAccount = await isolation.getTestAccount('destination');

    // Create agent wallet
    const createResult = await mcpClient.call('wallet_create', {
      name: 'tier3-multisign-test',
      network: 'testnet',
      policy: {
        max_amount_per_transaction_drops: '10000000000', // 10000 XRP
        require_cosign_above_drops: '1000000000',        // 1000 XRP
      },
    });

    agentWallet = { id: createResult.wallet_id, address: createResult.address };

    // Fund wallet generously for multi-sign fees
    await fundViaFaucet(agentWallet.address, 5000);
    await waitForLedgerClose();

    // Setup SignerList on-chain
    await setupSignerList(
      xrplClient,
      agentWallet.address,
      [
        { address: agentWallet.address, weight: 1 },
        { address: human1Account.address, weight: 1 },
        { address: human2Account.address, weight: 1 },
      ],
      2 // Quorum: 2 signatures required
    );

    // Configure multi-sign in MCP
    await mcpClient.call('wallet_configure_multisign', {
      wallet_id: agentWallet.id,
      signers: [
        { address: agentWallet.address, weight: 1, role: 'agent' },
        { address: human1Account.address, weight: 1, role: 'human_approver' },
        { address: human2Account.address, weight: 1, role: 'human_approver' },
      ],
      quorum: 2,
    });
  }, 180000); // 3 minute setup

  afterAll(async () => {
    // Note: Wallet deletion requires multi-sign approval in Tier 3
    // For cleanup, we skip wallet deletion or use master key
    await mcpClient.close();
    await xrplClient.disconnect();
    await isolation.teardown();
  });

  test('Initiate Tier 3 transaction - requires multi-sign', async () => {
    const payment = await buildPaymentTransaction(
      agentWallet.address,
      destinationAccount.address,
      '1500000000' // 1500 XRP - above Tier 3 threshold
    );

    const result = await mcpClient.call('wallet_sign', {
      wallet_address: agentWallet.address,
      unsigned_tx: payment.unsigned_blob,
      context: 'E2E test - high value transfer',
    });

    expect(result.status).toBe('pending_approval');
    expect(result.policy_tier).toBe(3);
    expect(result.requires_cosign).toBe(true);
    expect(result.approval_id).toMatch(/^[a-f0-9-]{36}$/);
    expect(result.quorum.required).toBe(2);
    expect(result.quorum.collected).toBe(0);
    expect(result.required_signers).toHaveLength(3);

    return result.approval_id; // Pass to next test
  });

  test('Human 1 adds signature', async () => {
    // Get pending request
    const statusResult = await mcpClient.call('wallet_sign_status', {
      wallet_address: agentWallet.address,
      filter: 'pending',
    });

    const pendingRequest = statusResult.pending_requests[0];
    expect(pendingRequest).toBeDefined();

    // Human 1 signs the transaction
    const humanSignature = human1Account.wallet.sign(
      pendingRequest.transaction.decoded,
      { multisign: true }
    );

    // Add signature to pending request
    const addResult = await mcpClient.call('wallet_sign_add_signature', {
      approval_id: pendingRequest.approval_id,
      signature: humanSignature.tx_blob,
      signer_address: human1Account.address,
    });

    expect(addResult.quorum.collected).toBe(1);
    expect(addResult.quorum.met).toBe(false);
  });

  test('Agent completes multi-sign transaction', async () => {
    // Get pending request
    const statusResult = await mcpClient.call('wallet_sign_status', {
      wallet_address: agentWallet.address,
      filter: 'pending',
    });

    const pendingRequest = statusResult.pending_requests[0];

    // Agent completes (adds own signature and submits)
    const completeResult = await mcpClient.call('wallet_sign_complete', {
      approval_id: pendingRequest.approval_id,
    });

    expect(completeResult.status).toBe('completed');
    expect(completeResult.tx_hash).toMatch(/^[A-F0-9]{64}$/);
    expect(completeResult.signers).toHaveLength(2);
    expect(completeResult.final_quorum).toBe(2);

    // Verify on ledger
    await xrplAssertions.assertTransactionOnLedger(
      completeResult.tx_hash,
      'tesSUCCESS'
    );

    // Verify multi-signed format on ledger
    const txResponse = await xrplClient.request({
      command: 'tx',
      transaction: completeResult.tx_hash,
    });

    expect(txResponse.result.Signers).toHaveLength(2);
    expect(txResponse.result.SigningPubKey).toBe('');
  }, 120000);

  test('Verify destination received funds', async () => {
    const destBalance = await destinationAccount.getBalance();
    const balanceXrp = parseFloat(dropsToXrp(destBalance));

    // Should have initial funding (1000 XRP) + 1500 XRP
    expect(balanceXrp).toBeGreaterThan(2400);
  });
});
```

---

### Scenario E2E-005: Key Rotation Workflow

```gherkin
Feature: Key Rotation
  As an AI agent
  I want to rotate wallet keys securely
  So that key compromise risk is minimized

Background:
  Given a running MCP server
  And an existing funded wallet with transaction history

Scenario: Secure key rotation with fund preservation
  # Preconditions
  Given wallet "rotation-test-wallet" with:
    | balance | 500 XRP |
    | regular_key | not_set |
  And the wallet has completed at least 1 transaction

  # Initiate rotation
  When I call wallet_rotate with:
    | parameter | value |
    | wallet_id | {wallet_id} |
    | reason | Security rotation |
  Then the response should have:
    | field | value |
    | status | completed |
    | new_address | {different_from_original} |
    | rotation_tx_hash | {hash} |
  And the SetRegularKey transaction should appear on ledger
  And the new regular key should match new_address derived key

  # Verify old key is disabled
  When I attempt to sign with old key material
  Then the signing should fail with "key_disabled"

  # Verify new key works
  When I sign a transaction with new key
  Then the signing should succeed
  And the transaction should be valid on XRPL

  # Verify funds preserved
  And wallet balance should remain ~500 XRP (minus fees)

Cleanup:
  - Delete test wallet
  - Close connections

Expected Duration: 3-4 minutes
```

**Implementation:**

```typescript
// e2e/scenarios/key-rotation.e2e.test.ts

describe('E2E-005: Key Rotation Workflow', () => {
  let isolation: TestIsolation;
  let mcpClient: McpClient;
  let xrplClient: Client;

  let testWallet: { id: string; address: string };
  let destinationAccount: TestAccount;
  let originalBalance: string;

  beforeAll(async () => {
    isolation = new TestIsolation();
    await isolation.setup();

    mcpClient = await McpClient.connect();
    xrplClient = await getXrplClient();
    destinationAccount = await isolation.getTestAccount('destination');

    // Create wallet
    const createResult = await mcpClient.call('wallet_create', {
      name: 'rotation-test-wallet',
      network: 'testnet',
    });

    testWallet = { id: createResult.wallet_id, address: createResult.address };

    // Fund wallet
    await fundViaFaucet(testWallet.address, 500);
    await waitForLedgerClose();

    // Make a transaction to create history
    const payment = await buildPaymentTransaction(
      testWallet.address,
      destinationAccount.address,
      '10000000' // 10 XRP
    );

    const signResult = await mcpClient.call('wallet_sign', {
      wallet_address: testWallet.address,
      unsigned_tx: payment.unsigned_blob,
    });

    await submitTransaction(signResult.signed_tx);
    await waitForLedgerClose();

    // Record balance before rotation
    const balanceResult = await mcpClient.call('wallet_get_balance', {
      wallet_address: testWallet.address,
    });
    originalBalance = balanceResult.balance_drops;
  }, 180000);

  afterAll(async () => {
    if (testWallet?.id) {
      await mcpClient.call('wallet_delete', {
        wallet_id: testWallet.id,
        confirm_delete: true,
      }).catch(() => {});
    }
    await mcpClient.close();
    await xrplClient.disconnect();
    await isolation.teardown();
  });

  test('Execute key rotation', async () => {
    const originalAddress = testWallet.address;

    const rotateResult = await mcpClient.call('wallet_rotate', {
      wallet_id: testWallet.id,
      reason: 'Security rotation - E2E test',
    });

    expect(rotateResult.status).toBe('completed');
    expect(rotateResult.new_address).toBeDefined();
    expect(rotateResult.new_address).not.toBe(originalAddress);
    expect(rotateResult.rotation_tx_hash).toMatch(/^[A-F0-9]{64}$/);

    // Verify SetRegularKey transaction on ledger
    await xrplAssertions.assertTransactionOnLedger(
      rotateResult.rotation_tx_hash,
      'tesSUCCESS'
    );

    // Verify regular key is set on account
    await xrplAssertions.assertRegularKeySet(
      originalAddress,
      rotateResult.new_address
    );

    // Update wallet address for subsequent tests
    testWallet.address = originalAddress; // Account address stays same
  }, 90000);

  test('New key can sign transactions', async () => {
    const payment = await buildPaymentTransaction(
      testWallet.address,
      destinationAccount.address,
      '5000000' // 5 XRP
    );

    const signResult = await mcpClient.call('wallet_sign', {
      wallet_address: testWallet.address,
      unsigned_tx: payment.unsigned_blob,
    });

    expect(signResult.status).toBe('approved');
    expect(signResult.signed_tx).toBeDefined();

    // Submit and verify
    const submitResult = await submitTransaction(signResult.signed_tx);
    await xrplAssertions.assertTransactionOnLedger(
      submitResult.tx_hash,
      'tesSUCCESS'
    );
  }, 60000);

  test('Funds preserved after rotation', async () => {
    const balanceResult = await mcpClient.call('wallet_get_balance', {
      wallet_address: testWallet.address,
    });

    const currentBalance = BigInt(balanceResult.balance_drops);
    const original = BigInt(originalBalance);

    // Should have lost only transaction fees (< 1 XRP worth)
    const maxFeeLoss = BigInt('1000000'); // 1 XRP max for all fees

    expect(currentBalance).toBeGreaterThan(original - maxFeeLoss - BigInt('15000000'));
    // Account for 10 XRP tx + 5 XRP tx + fees
  });
});
```

---

### Scenario E2E-006: Error Recovery and Resilience

```gherkin
Feature: Error Recovery and Resilience
  As an AI agent
  I want the system to recover gracefully from errors
  So that operations can continue after failures

Background:
  Given a running MCP server
  And a funded test wallet

Scenario: Recovery from network disconnection during signing
  # Preconditions
  Given wallet "resilience-test-wallet" is funded
  And a pending Tier 2 transaction exists

  # Simulate network issue
  When the XRPL connection is interrupted mid-operation
  Then the operation should return a retriable error
  And the wallet state should remain consistent

  # Retry after recovery
  When the XRPL connection is restored
  And I retry the signing operation
  Then the operation should succeed
  And no duplicate transactions should occur

Scenario: Recovery from transaction submission failure
  # Preconditions
  Given wallet "resilience-test-wallet" is funded

  # Submit transaction with network blip
  When I sign and attempt to submit a transaction
  And the submission fails with network error
  Then the system should not re-sign (replay protection)
  And I should be able to resubmit the same signed transaction

  # Verify no double-spend
  When the transaction is finally confirmed
  Then only one instance should appear on ledger

Scenario: Handling insufficient balance gracefully
  # Preconditions
  Given wallet with 5 XRP balance (just above reserve)

  # Attempt large transaction
  When I request signing for 10 XRP
  Then the response should have:
    | field | value |
    | status | rejected |
    | reason | insufficient_balance |
    | available_balance | ~3 XRP |
  And no partial signing should occur

Cleanup:
  - Delete test wallet
  - Close connections

Expected Duration: 4-5 minutes
```

**Implementation:**

```typescript
// e2e/scenarios/error-recovery.e2e.test.ts

describe('E2E-006: Error Recovery and Resilience', () => {
  let isolation: TestIsolation;
  let mcpClient: McpClient;
  let testWallet: { id: string; address: string };
  let destinationAccount: TestAccount;

  beforeAll(async () => {
    isolation = new TestIsolation();
    await isolation.setup();

    mcpClient = await McpClient.connect();
    destinationAccount = await isolation.getTestAccount('destination');

    // Create wallet
    const createResult = await mcpClient.call('wallet_create', {
      name: 'resilience-test-wallet',
      network: 'testnet',
    });

    testWallet = { id: createResult.wallet_id, address: createResult.address };
    await fundViaFaucet(testWallet.address, 100);
    await waitForLedgerClose();
  }, 120000);

  afterAll(async () => {
    if (testWallet?.id) {
      await mcpClient.call('wallet_delete', {
        wallet_id: testWallet.id,
        confirm_delete: true,
      }).catch(() => {});
    }
    await mcpClient.close();
    await isolation.teardown();
  });

  describe('Network disconnection recovery', () => {
    test('Operation returns retriable error on network failure', async () => {
      // Simulate network failure by using invalid endpoint temporarily
      const payment = await buildPaymentTransaction(
        testWallet.address,
        destinationAccount.address,
        '10000000' // 10 XRP
      );

      // This test validates error handling - actual network simulation
      // would require more infrastructure
      const signResult = await mcpClient.call('wallet_sign', {
        wallet_address: testWallet.address,
        unsigned_tx: payment.unsigned_blob,
      });

      // Should succeed in normal operation
      expect(signResult.status).toBe('approved');
    });
  });

  describe('Transaction submission failure recovery', () => {
    let signedTransaction: string;
    let transactionHash: string;

    test('Sign transaction for resubmission test', async () => {
      const payment = await buildPaymentTransaction(
        testWallet.address,
        destinationAccount.address,
        '5000000' // 5 XRP
      );

      const signResult = await mcpClient.call('wallet_sign', {
        wallet_address: testWallet.address,
        unsigned_tx: payment.unsigned_blob,
      });

      expect(signResult.status).toBe('approved');
      signedTransaction = signResult.signed_tx;
    });

    test('Same signed transaction can be resubmitted', async () => {
      // First submission
      const result1 = await submitTransaction(signedTransaction);
      transactionHash = result1.tx_hash;

      // Wait for confirmation
      await waitForLedgerClose();

      // Resubmission should either succeed (idempotent) or fail with tefALREADY
      try {
        await submitTransaction(signedTransaction);
        // If it succeeds, it's idempotent
      } catch (error) {
        // Expected: tefALREADY or similar
        expect(error.message).toMatch(/tefALREADY|tefPAST_SEQ|tesSUCCESS/);
      }
    });

    test('Only one transaction instance on ledger', async () => {
      // Query ledger for transactions from this account
      const client = await getXrplClient();

      const response = await client.request({
        command: 'account_tx',
        account: testWallet.address,
        limit: 10,
      });

      // Count transactions with same hash
      const matchingTxs = response.result.transactions.filter(
        tx => tx.tx?.hash === transactionHash
      );

      expect(matchingTxs.length).toBe(1);
    });
  });

  describe('Insufficient balance handling', () => {
    let lowBalanceWallet: { id: string; address: string };

    beforeAll(async () => {
      // Create wallet with minimal balance
      const createResult = await mcpClient.call('wallet_create', {
        name: 'low-balance-test',
        network: 'testnet',
      });

      lowBalanceWallet = {
        id: createResult.wallet_id,
        address: createResult.address,
      };

      // Fund with just above reserve (10 XRP reserve + 5 XRP spending)
      await fundViaFaucet(lowBalanceWallet.address, 15);
      await waitForLedgerClose();
    }, 60000);

    afterAll(async () => {
      if (lowBalanceWallet?.id) {
        await mcpClient.call('wallet_delete', {
          wallet_id: lowBalanceWallet.id,
          confirm_delete: true,
        }).catch(() => {});
      }
    });

    test('Large transaction rejected with insufficient balance', async () => {
      const payment = await buildPaymentTransaction(
        lowBalanceWallet.address,
        destinationAccount.address,
        '20000000' // 20 XRP - more than available
      );

      const result = await mcpClient.call('wallet_sign', {
        wallet_address: lowBalanceWallet.address,
        unsigned_tx: payment.unsigned_blob,
      });

      expect(result.status).toBe('rejected');
      expect(result.reason).toMatch(/insufficient_balance|tecUNFUNDED/i);
      expect(result.available_balance_drops).toBeDefined();

      // Verify available balance is reported
      const availableXrp = parseFloat(dropsToXrp(result.available_balance_drops));
      expect(availableXrp).toBeLessThan(20);
      expect(availableXrp).toBeGreaterThan(0);
    });
  });
});
```

---

### Scenario E2E-007: Policy Violation Prevention

```gherkin
Feature: Policy Violation Prevention
  As an AI agent
  I want policy violations to be prevented
  So that unauthorized operations cannot occur

Background:
  Given a running MCP server with strict policy
  And a funded wallet with destination allowlist

Scenario: Block transaction to non-allowlisted destination
  # Preconditions
  Given wallet policy includes:
    | setting | value |
    | allowed_destinations | [rAllowed123, rAllowed456] |

  # Attempt unauthorized destination
  When I request signing for 10 XRP to "rUnauthorized789"
  Then the response should have:
    | field | value |
    | status | rejected |
    | reason | destination_not_allowed |
    | violation_code | POLICY_DEST_NOT_ALLOWED |
  And the transaction should not be signed
  And the violation should be logged

Scenario: Block transaction exceeding per-transaction limit
  # Preconditions
  Given wallet policy includes:
    | setting | value |
    | max_amount_per_transaction_drops | 100000000 |

  # Attempt over-limit transaction
  When I request signing for 150 XRP
  Then the response should have:
    | field | value |
    | status | rejected |
    | reason | exceeds_transaction_limit |
    | max_allowed_drops | 100000000 |
    | requested_drops | 150000000 |

Scenario: Block transaction exceeding daily limit
  # Preconditions
  Given wallet policy includes:
    | setting | value |
    | daily_limit_drops | 200000000 |
  And 150 XRP has already been signed today

  # Attempt over-daily-limit transaction
  When I request signing for 100 XRP
  Then the response should have:
    | field | value |
    | status | rejected |
    | reason | exceeds_daily_limit |
    | daily_used_drops | 150000000 |
    | daily_limit_drops | 200000000 |
    | remaining_daily_drops | 50000000 |

Cleanup:
  - Delete test wallet
  - Close connections

Expected Duration: 3-4 minutes
```

**Implementation:**

```typescript
// e2e/scenarios/policy-violation.e2e.test.ts

describe('E2E-007: Policy Violation Prevention', () => {
  let isolation: TestIsolation;
  let mcpClient: McpClient;
  let testWallet: { id: string; address: string };
  let allowedDestination: TestAccount;
  let unauthorizedDestination: TestAccount;

  beforeAll(async () => {
    isolation = new TestIsolation();
    await isolation.setup();

    mcpClient = await McpClient.connect();
    allowedDestination = await isolation.getTestAccount('allowed');
    unauthorizedDestination = await isolation.getTestAccount('unauthorized');

    // Create wallet with strict policy
    const createResult = await mcpClient.call('wallet_create', {
      name: 'policy-violation-test',
      network: 'testnet',
      policy: {
        max_amount_per_transaction_drops: '100000000',  // 100 XRP max per tx
        daily_limit_drops: '200000000',                  // 200 XRP daily
        allowed_destinations: [allowedDestination.address],
        blocklist: [],
      },
    });

    testWallet = { id: createResult.wallet_id, address: createResult.address };
    await fundViaFaucet(testWallet.address, 500);
    await waitForLedgerClose();
  }, 120000);

  afterAll(async () => {
    if (testWallet?.id) {
      await mcpClient.call('wallet_delete', {
        wallet_id: testWallet.id,
        confirm_delete: true,
      }).catch(() => {});
    }
    await mcpClient.close();
    await isolation.teardown();
  });

  test('Block transaction to non-allowlisted destination', async () => {
    const payment = await buildPaymentTransaction(
      testWallet.address,
      unauthorizedDestination.address, // Not in allowlist
      '10000000' // 10 XRP
    );

    const result = await mcpClient.call('wallet_sign', {
      wallet_address: testWallet.address,
      unsigned_tx: payment.unsigned_blob,
    });

    expect(result.status).toBe('rejected');
    expect(result.reason).toMatch(/destination_not_allowed|POLICY_DEST_NOT_ALLOWED/i);
    expect(result.signed_tx).toBeUndefined();

    // Verify allowed destination works
    const allowedPayment = await buildPaymentTransaction(
      testWallet.address,
      allowedDestination.address,
      '10000000'
    );

    const allowedResult = await mcpClient.call('wallet_sign', {
      wallet_address: testWallet.address,
      unsigned_tx: allowedPayment.unsigned_blob,
    });

    expect(allowedResult.status).toBe('approved');
  });

  test('Block transaction exceeding per-transaction limit', async () => {
    const payment = await buildPaymentTransaction(
      testWallet.address,
      allowedDestination.address,
      '150000000' // 150 XRP - exceeds 100 XRP limit
    );

    const result = await mcpClient.call('wallet_sign', {
      wallet_address: testWallet.address,
      unsigned_tx: payment.unsigned_blob,
    });

    expect(result.status).toBe('rejected');
    expect(result.reason).toMatch(/exceeds_transaction_limit|POLICY_AMOUNT_EXCEEDED/i);
    expect(result.max_allowed_drops).toBe('100000000');
    expect(result.requested_drops).toBe('150000000');
    expect(result.signed_tx).toBeUndefined();
  });

  test('Block transaction exceeding daily limit', async () => {
    // First, use up most of the daily limit
    const payment1 = await buildPaymentTransaction(
      testWallet.address,
      allowedDestination.address,
      '90000000' // 90 XRP
    );

    const result1 = await mcpClient.call('wallet_sign', {
      wallet_address: testWallet.address,
      unsigned_tx: payment1.unsigned_blob,
    });
    expect(result1.status).toBe('approved');
    await submitTransaction(result1.signed_tx);

    const payment2 = await buildPaymentTransaction(
      testWallet.address,
      allowedDestination.address,
      '90000000' // Another 90 XRP (total 180)
    );

    const result2 = await mcpClient.call('wallet_sign', {
      wallet_address: testWallet.address,
      unsigned_tx: payment2.unsigned_blob,
    });
    expect(result2.status).toBe('approved');
    await submitTransaction(result2.signed_tx);

    // Now try to exceed daily limit
    const payment3 = await buildPaymentTransaction(
      testWallet.address,
      allowedDestination.address,
      '50000000' // 50 XRP - would exceed 200 XRP daily
    );

    const result3 = await mcpClient.call('wallet_sign', {
      wallet_address: testWallet.address,
      unsigned_tx: payment3.unsigned_blob,
    });

    expect(result3.status).toBe('rejected');
    expect(result3.reason).toMatch(/exceeds_daily_limit|POLICY_DAILY_LIMIT_EXCEEDED/i);
    expect(result3.daily_limit_drops).toBe('200000000');
    expect(BigInt(result3.daily_used_drops)).toBeGreaterThanOrEqual(BigInt('180000000'));
  }, 120000);
});
```

---

### Scenario E2E-008: Blocklist Enforcement

```gherkin
Feature: Blocklist Enforcement
  As an AI agent
  I want blocked addresses to be prevented
  So that transactions to known malicious addresses are stopped

Background:
  Given a running MCP server with blocklist configured
  And a funded test wallet

Scenario: Block transaction to blocklisted address
  # Preconditions
  Given wallet policy includes blocklist:
    | address | reason |
    | rMalicious123 | Known scam address |
    | rSanctioned456 | Regulatory blocklist |

  # Attempt blocked destination
  When I request signing for 10 XRP to "rMalicious123"
  Then the response should have:
    | field | value |
    | status | rejected |
    | reason | destination_blocked |
    | block_reason | Known scam address |
  And the transaction should not be signed
  And a security alert should be logged

Cleanup:
  - Delete test wallet
  - Close connections

Expected Duration: 2 minutes
```

---

### Scenario E2E-009: Audit Trail Verification

```gherkin
Feature: Audit Trail Verification
  As a compliance officer
  I want all operations logged immutably
  So that I can audit wallet activity

Background:
  Given a running MCP server with audit logging enabled
  And a funded test wallet

Scenario: Complete audit trail for transaction lifecycle
  # Preconditions
  Given audit log is empty for test wallet

  # Perform operations
  When I create a wallet
  Then audit log should contain "wallet_created" event

  When I fund the wallet
  And I sign a transaction
  Then audit log should contain "sign_requested" event
  And audit log should contain "sign_approved" event

  When I submit the transaction
  Then audit log should contain "tx_submitted" event
  And audit log should contain "tx_confirmed" event

  # Verify audit integrity
  When I verify the audit log hash chain
  Then all entries should have valid previous_hash links
  And no gaps should exist in sequence numbers
  And all entries should have valid timestamps

Cleanup:
  - Delete test wallet
  - Close connections

Expected Duration: 3 minutes
```

**Implementation:**

```typescript
// e2e/scenarios/audit-trail.e2e.test.ts

describe('E2E-009: Audit Trail Verification', () => {
  let isolation: TestIsolation;
  let mcpClient: McpClient;
  let testWallet: { id: string; address: string };
  let destinationAccount: TestAccount;

  beforeAll(async () => {
    isolation = new TestIsolation();
    await isolation.setup();

    mcpClient = await McpClient.connect();
    destinationAccount = await isolation.getTestAccount('destination');
  }, 60000);

  afterAll(async () => {
    if (testWallet?.id) {
      await mcpClient.call('wallet_delete', {
        wallet_id: testWallet.id,
        confirm_delete: true,
      }).catch(() => {});
    }
    await mcpClient.close();
    await isolation.teardown();
  });

  test('Wallet creation is logged', async () => {
    const createResult = await mcpClient.call('wallet_create', {
      name: 'audit-test-wallet',
      network: 'testnet',
    });

    testWallet = { id: createResult.wallet_id, address: createResult.address };

    // Query audit log
    const auditResult = await mcpClient.call('audit_query', {
      wallet_id: testWallet.id,
      event_types: ['wallet_created'],
    });

    expect(auditResult.entries).toHaveLength(1);
    expect(auditResult.entries[0].event_type).toBe('wallet_created');
    expect(auditResult.entries[0].wallet_id).toBe(testWallet.id);
    expect(auditResult.entries[0].timestamp).toBeDefined();
  });

  test('Transaction signing is logged', async () => {
    await fundViaFaucet(testWallet.address);
    await waitForLedgerClose();

    const payment = await buildPaymentTransaction(
      testWallet.address,
      destinationAccount.address,
      '10000000'
    );

    const signResult = await mcpClient.call('wallet_sign', {
      wallet_address: testWallet.address,
      unsigned_tx: payment.unsigned_blob,
    });

    // Query audit log
    const auditResult = await mcpClient.call('audit_query', {
      wallet_id: testWallet.id,
      event_types: ['sign_requested', 'sign_approved'],
    });

    expect(auditResult.entries.length).toBeGreaterThanOrEqual(2);

    const requestEntry = auditResult.entries.find(
      e => e.event_type === 'sign_requested'
    );
    const approveEntry = auditResult.entries.find(
      e => e.event_type === 'sign_approved'
    );

    expect(requestEntry).toBeDefined();
    expect(approveEntry).toBeDefined();
    expect(approveEntry.details.policy_tier).toBeDefined();
  }, 90000);

  test('Audit log hash chain is valid', async () => {
    const auditResult = await mcpClient.call('audit_query', {
      wallet_id: testWallet.id,
      include_hash_verification: true,
    });

    // Verify hash chain
    expect(auditResult.hash_chain_valid).toBe(true);

    // Verify sequence numbers are monotonic
    const sequences = auditResult.entries.map(e => e.sequence_number);
    for (let i = 1; i < sequences.length; i++) {
      expect(sequences[i]).toBe(sequences[i - 1] + 1);
    }

    // Verify timestamps are chronological
    const timestamps = auditResult.entries.map(e => new Date(e.timestamp));
    for (let i = 1; i < timestamps.length; i++) {
      expect(timestamps[i].getTime()).toBeGreaterThanOrEqual(
        timestamps[i - 1].getTime()
      );
    }
  });

  test('Sensitive data excluded from audit logs', async () => {
    const auditResult = await mcpClient.call('audit_query', {
      wallet_id: testWallet.id,
    });

    // Check no sensitive data in any entry
    for (const entry of auditResult.entries) {
      const entryStr = JSON.stringify(entry);

      // No private keys (hex strings of key length)
      expect(entryStr).not.toMatch(/[a-fA-F0-9]{64}/);

      // No seed phrases (word patterns)
      expect(entryStr).not.toMatch(/(abandon|ability|able)/);

      // No passwords
      expect(entryStr).not.toMatch(/password/i);
    }
  });
});
```

---

### Scenario E2E-010: Rate Limiting Under Load

```gherkin
Feature: Rate Limiting Under Load
  As a system operator
  I want rate limits enforced even under load
  So that the system remains stable and fair

Background:
  Given a running MCP server with rate limiting enabled
  And multiple test wallets

Scenario: Rate limits prevent abuse
  # Preconditions
  Given rate limit configuration:
    | tier | limit | window |
    | STANDARD | 100/min | sliding |
    | STRICT | 20/min | sliding |
    | CRITICAL | 5/5min | sliding |

  # Test STANDARD tier (read operations)
  When I make 100 wallet_get_balance requests in 1 minute
  Then all 100 should succeed
  When I make the 101st request
  Then it should be rate limited with 429 response
  And response should include Retry-After header

  # Test STRICT tier (write operations)
  When I make 20 wallet_sign requests in 1 minute
  Then all 20 should be processed (approved or pending)
  When I make the 21st request
  Then it should be rate limited

  # Test recovery
  When I wait for rate limit window to pass
  Then requests should succeed again

Cleanup:
  - Delete test wallets
  - Close connections

Expected Duration: 5-7 minutes
```

**Implementation:**

```typescript
// e2e/scenarios/rate-limiting.e2e.test.ts

describe('E2E-010: Rate Limiting Under Load', () => {
  let isolation: TestIsolation;
  let mcpClient: McpClient;
  let testWallet: { id: string; address: string };

  beforeAll(async () => {
    isolation = new TestIsolation();
    await isolation.setup();

    mcpClient = await McpClient.connect();

    // Create wallet
    const createResult = await mcpClient.call('wallet_create', {
      name: 'rate-limit-test',
      network: 'testnet',
    });

    testWallet = { id: createResult.wallet_id, address: createResult.address };
    await fundViaFaucet(testWallet.address);
    await waitForLedgerClose();
  }, 120000);

  afterAll(async () => {
    if (testWallet?.id) {
      await mcpClient.call('wallet_delete', {
        wallet_id: testWallet.id,
        confirm_delete: true,
      }).catch(() => {});
    }
    await mcpClient.close();
    await isolation.teardown();
  });

  test('STANDARD tier rate limit (read operations)', async () => {
    const results: Array<{ success: boolean; status?: number }> = [];

    // Make requests up to limit
    const promises = [];
    for (let i = 0; i < 105; i++) {
      promises.push(
        mcpClient.call('wallet_get_balance', {
          wallet_address: testWallet.address,
        })
        .then(() => ({ success: true }))
        .catch((e) => ({ success: false, status: e.status || 429 }))
      );
    }

    const outcomes = await Promise.all(promises);

    const successes = outcomes.filter(o => o.success);
    const rateLimited = outcomes.filter(o => !o.success && o.status === 429);

    // Should have ~100 successes and ~5 rate limited
    expect(successes.length).toBeGreaterThanOrEqual(95);
    expect(rateLimited.length).toBeGreaterThan(0);
  }, 120000);

  test('Rate limit recovery after window', async () => {
    // Wait for rate limit window to expire (>1 minute)
    await sleep(65000);

    // Should succeed now
    const result = await mcpClient.call('wallet_get_balance', {
      wallet_address: testWallet.address,
    });

    expect(result.balance_drops).toBeDefined();
  }, 90000);

  test('Rate limit headers in response', async () => {
    const response = await mcpClient.callWithHeaders('wallet_get_balance', {
      wallet_address: testWallet.address,
    });

    expect(response.headers['x-ratelimit-limit']).toBeDefined();
    expect(response.headers['x-ratelimit-remaining']).toBeDefined();
    expect(response.headers['x-ratelimit-reset']).toBeDefined();

    const remaining = parseInt(response.headers['x-ratelimit-remaining']);
    expect(remaining).toBeGreaterThanOrEqual(0);
    expect(remaining).toBeLessThanOrEqual(100);
  });
});
```

---

## 6. CI/CD Integration

### 6.1 GitHub Actions Workflow

```yaml
# .github/workflows/e2e-tests.yml

name: E2E Tests

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]
  schedule:
    # Nightly extended tests at 2 AM UTC
    - cron: '0 2 * * *'

env:
  XRPL_TESTNET_URL: wss://s.altnet.rippletest.net:51233
  XRPL_FAUCET_URL: https://faucet.altnet.rippletest.net/accounts

jobs:
  e2e-smoke:
    name: E2E Smoke Tests
    runs-on: ubuntu-latest
    timeout-minutes: 15

    steps:
      - uses: actions/checkout@v4

      - name: Setup Node.js
        uses: actions/setup-node@v4
        with:
          node-version: '20'
          cache: 'npm'

      - name: Install dependencies
        run: npm ci

      - name: Build
        run: npm run build

      - name: Run E2E Smoke Tests
        run: npm run test:e2e:smoke
        env:
          E2E_TEST_PASSWORD: ${{ secrets.E2E_TEST_PASSWORD }}

      - name: Upload test results
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: e2e-smoke-results
          path: test-results/

  e2e-core:
    name: E2E Core Tests
    runs-on: ubuntu-latest
    timeout-minutes: 30
    needs: e2e-smoke

    steps:
      - uses: actions/checkout@v4

      - name: Setup Node.js
        uses: actions/setup-node@v4
        with:
          node-version: '20'
          cache: 'npm'

      - name: Install dependencies
        run: npm ci

      - name: Build
        run: npm run build

      - name: Run E2E Core Tests
        run: npm run test:e2e:core
        env:
          E2E_TEST_PASSWORD: ${{ secrets.E2E_TEST_PASSWORD }}

      - name: Upload test results
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: e2e-core-results
          path: test-results/

  e2e-extended:
    name: E2E Extended Tests
    runs-on: ubuntu-latest
    timeout-minutes: 60
    # Only run on schedule or manual trigger
    if: github.event_name == 'schedule' || github.event_name == 'workflow_dispatch'

    steps:
      - uses: actions/checkout@v4

      - name: Setup Node.js
        uses: actions/setup-node@v4
        with:
          node-version: '20'
          cache: 'npm'

      - name: Install dependencies
        run: npm ci

      - name: Build
        run: npm run build

      - name: Run E2E Extended Tests
        run: npm run test:e2e:extended
        env:
          E2E_TEST_PASSWORD: ${{ secrets.E2E_TEST_PASSWORD }}

      - name: Upload test results
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: e2e-extended-results
          path: test-results/

      - name: Notify on failure
        if: failure()
        uses: slackapi/slack-github-action@v1
        with:
          payload: |
            {
              "text": "E2E Extended Tests Failed",
              "blocks": [
                {
                  "type": "section",
                  "text": {
                    "type": "mrkdwn",
                    "text": ":x: E2E Extended Tests failed on `${{ github.ref }}`"
                  }
                }
              ]
            }
        env:
          SLACK_WEBHOOK_URL: ${{ secrets.SLACK_WEBHOOK }}
```

### 6.2 Test Scripts (package.json)

```json
{
  "scripts": {
    "test:e2e": "vitest run --config vitest.e2e.config.ts",
    "test:e2e:smoke": "vitest run --config vitest.e2e.config.ts --testNamePattern='E2E-00[12]'",
    "test:e2e:core": "vitest run --config vitest.e2e.config.ts --testNamePattern='E2E-00[1-5]'",
    "test:e2e:extended": "vitest run --config vitest.e2e.config.ts",
    "test:e2e:watch": "vitest --config vitest.e2e.config.ts",
    "test:e2e:ui": "vitest --config vitest.e2e.config.ts --ui"
  }
}
```

### 6.3 Vitest E2E Configuration

```typescript
// vitest.e2e.config.ts

import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    include: ['e2e/**/*.e2e.test.ts'],
    exclude: ['node_modules', 'dist'],

    // Long timeout for E2E tests
    testTimeout: 120000, // 2 minutes per test
    hookTimeout: 180000, // 3 minutes for setup/teardown

    // Sequential execution to avoid testnet rate limits
    pool: 'forks',
    poolOptions: {
      forks: {
        singleFork: true,
      },
    },

    // Retry flaky tests once
    retry: 1,

    // Reporter configuration
    reporters: ['verbose', 'json', 'html'],
    outputFile: {
      json: 'test-results/e2e-results.json',
      html: 'test-results/e2e-report.html',
    },

    // Global setup/teardown
    globalSetup: './e2e/setup/global-setup.ts',
    globalTeardown: './e2e/setup/global-teardown.ts',

    // Environment
    env: {
      NODE_ENV: 'test',
      LOG_LEVEL: 'debug',
    },
  },
});
```

---

## 7. Performance Benchmarks

### 7.1 Benchmark Definitions

| Operation | Target P50 | Target P95 | Target P99 | Threshold |
|-----------|------------|------------|------------|-----------|
| wallet_create | < 500ms | < 1s | < 2s | < 3s |
| wallet_get_balance | < 200ms | < 500ms | < 1s | < 2s |
| wallet_sign (Tier 1) | < 300ms | < 500ms | < 1s | < 2s |
| wallet_sign (Tier 2) | < 500ms | < 1s | < 2s | < 3s |
| wallet_rotate | < 5s | < 10s | < 15s | < 20s |
| TX submission | < 2s | < 4s | < 8s | < 15s |
| TX confirmation | < 5s | < 10s | < 30s | < 60s |

### 7.2 Benchmark Test Implementation

```typescript
// e2e/benchmarks/performance.bench.ts

import { bench, describe } from 'vitest';

describe('E2E Performance Benchmarks', () => {
  let mcpClient: McpClient;
  let testWallet: { id: string; address: string };

  beforeAll(async () => {
    mcpClient = await McpClient.connect();

    // Pre-create wallet for benchmarks
    const result = await mcpClient.call('wallet_create', {
      name: 'benchmark-wallet',
      network: 'testnet',
    });

    testWallet = { id: result.wallet_id, address: result.address };
    await fundViaFaucet(testWallet.address);
    await waitForLedgerClose();
  });

  afterAll(async () => {
    await mcpClient.call('wallet_delete', {
      wallet_id: testWallet.id,
      confirm_delete: true,
    }).catch(() => {});
    await mcpClient.close();
  });

  bench('wallet_get_balance', async () => {
    await mcpClient.call('wallet_get_balance', {
      wallet_address: testWallet.address,
    });
  }, {
    time: 30000,    // 30 seconds
    iterations: 50,  // At least 50 iterations
  });

  bench('wallet_sign (Tier 1)', async () => {
    const payment = await buildPaymentTransaction(
      testWallet.address,
      'rDestination...',
      '1000000' // 1 XRP
    );

    await mcpClient.call('wallet_sign', {
      wallet_address: testWallet.address,
      unsigned_tx: payment.unsigned_blob,
    });
  }, {
    time: 60000,
    iterations: 20,
  });

  bench('wallet_create', async () => {
    const result = await mcpClient.call('wallet_create', {
      name: `bench-${Date.now()}`,
      network: 'testnet',
    });

    // Cleanup
    await mcpClient.call('wallet_delete', {
      wallet_id: result.wallet_id,
      confirm_delete: true,
    });
  }, {
    time: 60000,
    iterations: 10,
  });
});
```

### 7.3 Performance CI Job

```yaml
# .github/workflows/performance.yml

name: Performance Benchmarks

on:
  schedule:
    - cron: '0 3 * * 0'  # Weekly Sunday 3 AM
  workflow_dispatch:

jobs:
  benchmark:
    runs-on: ubuntu-latest
    timeout-minutes: 45

    steps:
      - uses: actions/checkout@v4

      - name: Setup Node.js
        uses: actions/setup-node@v4
        with:
          node-version: '20'
          cache: 'npm'

      - name: Install dependencies
        run: npm ci

      - name: Build
        run: npm run build

      - name: Run Benchmarks
        run: npm run bench:e2e
        env:
          E2E_TEST_PASSWORD: ${{ secrets.E2E_TEST_PASSWORD }}

      - name: Compare with baseline
        run: npm run bench:compare

      - name: Upload benchmark results
        uses: actions/upload-artifact@v4
        with:
          name: benchmark-results
          path: benchmark-results/

      - name: Alert on regression
        if: failure()
        uses: slackapi/slack-github-action@v1
        with:
          payload: |
            {
              "text": ":warning: Performance regression detected in E2E benchmarks"
            }
        env:
          SLACK_WEBHOOK_URL: ${{ secrets.SLACK_WEBHOOK }}
```

---

## Appendix

### A. Test Scenario Summary

| ID | Scenario | Category | Priority | Duration |
|----|----------|----------|----------|----------|
| E2E-001 | Complete Wallet Lifecycle | Core | Critical | 3-5 min |
| E2E-002 | Tier 1 Policy Enforcement | Policy | Critical | 2-3 min |
| E2E-003 | Tier 2 Policy Enforcement | Policy | Critical | 3-4 min |
| E2E-004 | Tier 3 Multi-Sign Workflow | Multi-Sign | Critical | 5-7 min |
| E2E-005 | Key Rotation Workflow | Security | High | 3-4 min |
| E2E-006 | Error Recovery | Resilience | High | 4-5 min |
| E2E-007 | Policy Violation Prevention | Policy | Critical | 3-4 min |
| E2E-008 | Blocklist Enforcement | Security | High | 2 min |
| E2E-009 | Audit Trail Verification | Compliance | High | 3 min |
| E2E-010 | Rate Limiting Under Load | Performance | Medium | 5-7 min |

### B. Test Environment Requirements

| Requirement | Specification |
|-------------|---------------|
| Node.js | v20+ |
| npm | v10+ |
| XRPL Testnet Access | wss://s.altnet.rippletest.net:51233 |
| Testnet Faucet | https://faucet.altnet.rippletest.net |
| Test Account Funding | 100-1000 XRP per account |
| Network Bandwidth | Stable connection to testnet |
| Disk Space | 1GB for test artifacts |
| Memory | 4GB minimum |

### C. Troubleshooting Guide

| Issue | Cause | Solution |
|-------|-------|----------|
| Faucet rate limiting | Too many funding requests | Wait 10 minutes, use account pool |
| Transaction timeout | Network congestion | Increase timeout, retry with backoff |
| Sequence error | Concurrent transactions | Serialize transactions per account |
| Test flakiness | Ledger close timing | Add waitForLedgerClose() |
| Memory issues | Large test data | Cleanup between tests |

### D. Related Documents

- [Unit Test Patterns](./test-patterns-unit.md)
- [Security Requirements](../../security/security-requirements.md)
- [Multi-Sign Specification](./multi-sign-spec.md)
- [Policy Schema](../../api/policy-schema.md)
- [wallet_sign Tool](../../api/tools/wallet-sign.md)

---

## Document History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0.0 | 2026-01-28 | QA & DevOps Engineer | Initial E2E test scenarios specification |

---

*This document defines comprehensive end-to-end test scenarios for the XRPL Agent Wallet MCP server. All scenarios test against real XRPL testnet infrastructure to ensure production-ready reliability.*
