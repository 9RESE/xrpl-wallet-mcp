# Unit Test Patterns Specification

## Document Information

| Field | Value |
|-------|-------|
| **Document ID** | SPEC-TEST-UNIT-001 |
| **Version** | 1.0.0 |
| **Status** | Draft |
| **Created** | 2026-01-28 |
| **Last Updated** | 2026-01-28 |
| **Author** | QA/DevOps Engineer |
| **Reviewers** | Tech Lead, Security Engineer |

## Table of Contents

1. [Testing Philosophy](#1-testing-philosophy)
2. [Framework Configuration](#2-framework-configuration)
3. [Test Organization](#3-test-organization)
4. [Mocking Strategies](#4-mocking-strategies)
5. [Test Patterns by Component](#5-test-patterns-by-component)
6. [Assertion Patterns](#6-assertion-patterns)
7. [Coverage Targets](#7-coverage-targets)
8. [Example Test Files](#8-example-test-files)
9. [Best Practices](#9-best-practices)

---

## 1. Testing Philosophy

### 1.1 Core Principles

Unit tests in the xrpl-wallet-mcp project adhere to the following fundamental principles:

#### Isolated
- Each test operates independently without relying on external services
- No network calls to actual XRPL nodes
- No file system side effects outside of controlled test directories
- Tests can run in any order without affecting each other

#### Fast
- Target execution time: < 100ms per test
- Total unit test suite: < 30 seconds
- Use in-memory implementations where possible
- Avoid artificial delays or timeouts in tests

#### Deterministic
- Same inputs always produce same outputs
- No reliance on system time (use mocked clocks)
- No random values without seeding
- Consistent behavior across different environments

### 1.2 Security-First Testing

Given the cryptographic nature of wallet operations:

- **Never use production keys in tests**
- **Use well-known test vectors for cryptographic operations**
- **Verify secure memory handling (SecureBuffer clearing)**
- **Test error paths thoroughly** - attackers exploit edge cases
- **Validate input sanitization exhaustively**

### 1.3 Test Pyramid

```
         /\
        /  \     E2E Tests (5%)
       /----\    - Full MCP integration
      /      \
     /--------\  Integration Tests (15%)
    /          \ - Component interaction
   /------------\
  /              \ Unit Tests (80%)
 /----------------\ - Individual functions
```

---

## 2. Framework Configuration

### 2.1 Framework Choice: Vitest

**Why Vitest:**
- Native TypeScript support
- Fast execution with Vite's transformation
- Compatible with Jest API (familiar patterns)
- Built-in code coverage with v8
- Watch mode with intelligent re-running
- First-class ESM support

### 2.2 Configuration

```typescript
// vitest.config.ts
import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    // Global test configuration
    globals: true,
    environment: 'node',

    // Include patterns
    include: ['src/**/*.test.ts', 'src/**/*.spec.ts'],
    exclude: ['node_modules', 'dist', '**/*.e2e.test.ts'],

    // Coverage configuration
    coverage: {
      provider: 'v8',
      reporter: ['text', 'json', 'html', 'lcov'],
      reportsDirectory: './coverage',

      // Coverage thresholds
      thresholds: {
        global: {
          branches: 90,
          functions: 90,
          lines: 90,
          statements: 90,
        },
        // Security-critical paths require higher coverage
        './src/keystore/**/*.ts': {
          branches: 95,
          functions: 95,
          lines: 95,
          statements: 95,
        },
        './src/crypto/**/*.ts': {
          branches: 95,
          functions: 95,
          lines: 95,
          statements: 95,
        },
        './src/policy/**/*.ts': {
          branches: 95,
          functions: 95,
          lines: 95,
          statements: 95,
        },
      },

      // Exclude from coverage
      exclude: [
        'node_modules/**',
        'dist/**',
        '**/*.d.ts',
        '**/*.test.ts',
        '**/*.spec.ts',
        '**/types/**',
        '**/index.ts', // Re-export files
      ],
    },

    // Test timeouts
    testTimeout: 5000,
    hookTimeout: 10000,

    // Parallel execution
    pool: 'threads',
    poolOptions: {
      threads: {
        singleThread: false,
        isolate: true,
      },
    },

    // Setup files
    setupFiles: ['./src/test/setup.ts'],
    globalSetup: './src/test/global-setup.ts',

    // Retry configuration (for CI)
    retry: process.env.CI ? 2 : 0,

    // Reporter configuration
    reporters: process.env.CI
      ? ['default', 'junit']
      : ['default'],
    outputFile: {
      junit: './test-results/junit.xml',
    },
  },
});
```

### 2.3 Setup Files

```typescript
// src/test/setup.ts
import { beforeAll, afterAll, beforeEach, afterEach, vi } from 'vitest';

// Reset all mocks between tests
beforeEach(() => {
  vi.clearAllMocks();
});

afterEach(() => {
  vi.restoreAllMocks();
});

// Global test utilities
declare global {
  // Add custom matchers type declarations
  namespace Vi {
    interface Assertion {
      toBeSecurelyCleared(): void;
      toBeValidXRPLAddress(): void;
    }
  }
}

// Custom matchers
expect.extend({
  toBeSecurelyCleared(received: Buffer) {
    const isCleared = received.every(byte => byte === 0);
    return {
      pass: isCleared,
      message: () =>
        isCleared
          ? `expected buffer not to be cleared`
          : `expected buffer to be cleared (all zeros)`,
    };
  },

  toBeValidXRPLAddress(received: string) {
    const xrplAddressRegex = /^r[1-9A-HJ-NP-Za-km-z]{24,34}$/;
    const isValid = xrplAddressRegex.test(received);
    return {
      pass: isValid,
      message: () =>
        isValid
          ? `expected ${received} not to be a valid XRPL address`
          : `expected ${received} to be a valid XRPL address`,
    };
  },
});
```

```typescript
// src/test/global-setup.ts
export default async function globalSetup() {
  // Set test environment variables
  process.env.NODE_ENV = 'test';
  process.env.LOG_LEVEL = 'silent';

  // Ensure test directories exist
  const { mkdir } = await import('fs/promises');
  await mkdir('./test-data', { recursive: true });
}

export async function teardown() {
  // Cleanup test directories
  const { rm } = await import('fs/promises');
  await rm('./test-data', { recursive: true, force: true });
}
```

### 2.4 Package.json Scripts

```json
{
  "scripts": {
    "test": "vitest run",
    "test:watch": "vitest watch",
    "test:ui": "vitest --ui",
    "test:coverage": "vitest run --coverage",
    "test:ci": "vitest run --coverage --reporter=junit",
    "test:security": "vitest run --coverage src/keystore src/crypto src/policy"
  }
}
```

---

## 3. Test Organization

### 3.1 File Structure

```
src/
├── keystore/
│   ├── local-keystore.ts
│   ├── local-keystore.test.ts      # Unit tests
│   └── __mocks__/
│       └── fs.ts                    # Module mocks
├── policy/
│   ├── policy-engine.ts
│   ├── policy-engine.test.ts
│   └── tier-classifier.test.ts
├── audit/
│   ├── audit-logger.ts
│   └── audit-logger.test.ts
├── validators/
│   ├── schemas.ts
│   └── schemas.test.ts
├── xrpl/
│   ├── xrpl-client.ts
│   ├── xrpl-client.test.ts
│   └── __mocks__/
│       └── xrpl.ts
└── test/
    ├── setup.ts
    ├── global-setup.ts
    ├── fixtures/
    │   ├── wallets.ts               # Test wallet data
    │   ├── transactions.ts          # Test transactions
    │   └── policies.ts              # Test policies
    └── helpers/
        ├── mock-fs.ts
        ├── mock-time.ts
        └── mock-xrpl.ts
```

### 3.2 Describe/It Structure

Use a consistent hierarchical structure:

```typescript
describe('ComponentName', () => {
  // Group by method/feature
  describe('methodName', () => {
    // Group by scenario
    describe('when condition', () => {
      // Individual test cases
      it('should expected behavior', () => {
        // Arrange, Act, Assert
      });
    });

    describe('error handling', () => {
      it('should throw ErrorType when invalid input', () => {
        // Error case testing
      });
    });
  });
});
```

### 3.3 Naming Conventions

```typescript
// File names: component-name.test.ts

// Describe blocks: Use the class/module name
describe('LocalFileKeystoreProvider', () => {

// Nested describes: Use method names or conditions
describe('createWallet', () => {
describe('when passphrase is valid', () => {

// It blocks: Start with "should"
it('should create a new encrypted wallet file', () => {
it('should return the wallet address', () => {
it('should throw InvalidPassphraseError when passphrase is empty', () => {
```

### 3.4 Arrange-Act-Assert Pattern

```typescript
it('should encrypt wallet data with AES-256-GCM', async () => {
  // Arrange
  const keystore = new LocalFileKeystoreProvider({
    keystorePath: testDir,
    encryptionConfig: defaultConfig,
  });
  const passphrase = 'test-passphrase-123';

  // Act
  const result = await keystore.createWallet(passphrase);

  // Assert
  expect(result.address).toBeValidXRPLAddress();
  expect(result.encrypted).toBe(true);
});
```

---

## 4. Mocking Strategies

### 4.1 File System Mocking

Use memfs for in-memory file system operations:

```typescript
// src/test/helpers/mock-fs.ts
import { vol, fs as memfs } from 'memfs';
import { vi } from 'vitest';

export function createMockFileSystem(initialFiles: Record<string, string> = {}) {
  // Reset volume
  vol.reset();

  // Create initial files
  vol.fromJSON(initialFiles, '/test');

  // Mock fs/promises
  vi.mock('fs/promises', () => ({
    readFile: vi.fn((path: string, encoding?: string) =>
      memfs.promises.readFile(path, encoding)),
    writeFile: vi.fn((path: string, data: string | Buffer) =>
      memfs.promises.writeFile(path, data)),
    mkdir: vi.fn((path: string, options?: { recursive?: boolean }) =>
      memfs.promises.mkdir(path, options)),
    access: vi.fn((path: string) =>
      memfs.promises.access(path)),
    unlink: vi.fn((path: string) =>
      memfs.promises.unlink(path)),
    rename: vi.fn((oldPath: string, newPath: string) =>
      memfs.promises.rename(oldPath, newPath)),
    readdir: vi.fn((path: string) =>
      memfs.promises.readdir(path)),
    stat: vi.fn((path: string) =>
      memfs.promises.stat(path)),
  }));

  return {
    vol,
    fs: memfs,
    getFileContent: (path: string) => vol.readFileSync(path, 'utf8'),
    fileExists: (path: string) => {
      try {
        vol.statSync(path);
        return true;
      } catch {
        return false;
      }
    },
    reset: () => vol.reset(),
  };
}

// Usage in tests
describe('LocalFileKeystoreProvider', () => {
  let mockFs: ReturnType<typeof createMockFileSystem>;

  beforeEach(() => {
    mockFs = createMockFileSystem({
      '/test/keystores/.gitkeep': '',
    });
  });

  afterEach(() => {
    mockFs.reset();
    vi.restoreAllMocks();
  });

  it('should write wallet to file system', async () => {
    const keystore = new LocalFileKeystoreProvider({
      keystorePath: '/test/keystores',
    });

    await keystore.createWallet('passphrase');

    expect(mockFs.fileExists('/test/keystores/wallet.enc')).toBe(true);
  });
});
```

### 4.2 XRPL Client Mocking

```typescript
// src/test/helpers/mock-xrpl.ts
import { vi } from 'vitest';
import type { Client, Wallet, TxResponse } from 'xrpl';

export interface MockXRPLClientOptions {
  connected?: boolean;
  networkId?: number;
  serverUrl?: string;
  accountInfo?: Record<string, unknown>;
  submitResponse?: Partial<TxResponse>;
}

export function createMockXRPLClient(options: MockXRPLClientOptions = {}) {
  const {
    connected = true,
    networkId = 1,
    serverUrl = 'wss://testnet.xrpl.org',
    accountInfo = { Balance: '1000000000' },
    submitResponse = {
      result: {
        engine_result: 'tesSUCCESS',
        tx_json: { hash: 'mock-hash' },
      },
    },
  } = options;

  const mockClient = {
    isConnected: vi.fn().mockReturnValue(connected),
    connect: vi.fn().mockResolvedValue(undefined),
    disconnect: vi.fn().mockResolvedValue(undefined),
    request: vi.fn().mockImplementation(async (request: { command: string }) => {
      switch (request.command) {
        case 'account_info':
          return { result: { account_data: accountInfo } };
        case 'server_info':
          return {
            result: {
              info: {
                network_id: networkId,
                server_state: 'full',
              },
            },
          };
        case 'fee':
          return { result: { drops: { base_fee: '10' } } };
        default:
          throw new Error(`Unmocked command: ${request.command}`);
      }
    }),
    submit: vi.fn().mockResolvedValue(submitResponse),
    submitAndWait: vi.fn().mockResolvedValue(submitResponse),
    autofill: vi.fn().mockImplementation(async (tx) => ({
      ...tx,
      Fee: '12',
      Sequence: 1,
      LastLedgerSequence: 1000,
    })),
    getServerInfo: vi.fn().mockResolvedValue({
      info: { network_id: networkId },
    }),
    url: serverUrl,

    // Event handling
    on: vi.fn(),
    off: vi.fn(),
    once: vi.fn(),
    removeAllListeners: vi.fn(),
  } as unknown as Client;

  // Mock the xrpl module
  vi.mock('xrpl', async () => {
    const actual = await vi.importActual('xrpl');
    return {
      ...actual,
      Client: vi.fn().mockImplementation(() => mockClient),
    };
  });

  return {
    client: mockClient,

    // Helper methods for test setup
    setConnected: (value: boolean) => {
      mockClient.isConnected.mockReturnValue(value);
    },

    setAccountBalance: (balance: string) => {
      mockClient.request.mockImplementation(async (req: { command: string }) => {
        if (req.command === 'account_info') {
          return { result: { account_data: { Balance: balance } } };
        }
        return { result: {} };
      });
    },

    setSubmitError: (error: Error) => {
      mockClient.submit.mockRejectedValue(error);
      mockClient.submitAndWait.mockRejectedValue(error);
    },

    setSubmitResponse: (response: Partial<TxResponse>) => {
      mockClient.submit.mockResolvedValue(response);
      mockClient.submitAndWait.mockResolvedValue(response);
    },

    simulateDisconnect: () => {
      mockClient.isConnected.mockReturnValue(false);
      // Trigger disconnect event if handlers registered
      const disconnectHandler = mockClient.on.mock.calls.find(
        ([event]) => event === 'disconnected'
      )?.[1];
      if (disconnectHandler) {
        disconnectHandler();
      }
    },

    reset: () => {
      vi.clearAllMocks();
    },
  };
}

// Mock wallet creation
export function createMockWallet(overrides: Partial<Wallet> = {}): Wallet {
  return {
    address: 'rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh',
    publicKey: 'ED5F5AC8B98974A3CA843326D9B88CEBD36EFCFCD6F7D7A8C3C4F9E5C6A8B9D7E2',
    privateKey: 'ED1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF',
    seed: 'sEdTM1uX8pu2do5XvTnutH6HsouMaM2',
    classicAddress: 'rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh',
    ...overrides,
  } as Wallet;
}
```

### 4.3 Time/Clock Mocking

```typescript
// src/test/helpers/mock-time.ts
import { vi, beforeEach, afterEach } from 'vitest';

export interface MockTimeOptions {
  initialTime?: Date | number;
  autoAdvance?: boolean;
  advanceMs?: number;
}

export function createMockTime(options: MockTimeOptions = {}) {
  const {
    initialTime = new Date('2026-01-28T00:00:00.000Z'),
    autoAdvance = false,
    advanceMs = 1000,
  } = options;

  let currentTime = new Date(initialTime).getTime();

  // Use fake timers
  vi.useFakeTimers();
  vi.setSystemTime(currentTime);

  return {
    // Get current mocked time
    now: () => currentTime,

    // Advance time by milliseconds
    advance: (ms: number) => {
      currentTime += ms;
      vi.setSystemTime(currentTime);
      vi.advanceTimersByTime(ms);
    },

    // Advance to specific time
    advanceTo: (time: Date | number) => {
      const targetTime = new Date(time).getTime();
      const diff = targetTime - currentTime;
      if (diff > 0) {
        currentTime = targetTime;
        vi.setSystemTime(currentTime);
        vi.advanceTimersByTime(diff);
      }
    },

    // Run all pending timers
    runAll: () => {
      vi.runAllTimers();
    },

    // Run only pending timers (no new ones)
    runPending: () => {
      vi.runOnlyPendingTimers();
    },

    // Restore real timers
    restore: () => {
      vi.useRealTimers();
    },

    // Get the date object
    getDate: () => new Date(currentTime),
  };
}

// Usage in tests
describe('RateLimiter', () => {
  let mockTime: ReturnType<typeof createMockTime>;

  beforeEach(() => {
    mockTime = createMockTime({
      initialTime: new Date('2026-01-28T00:00:00Z'),
    });
  });

  afterEach(() => {
    mockTime.restore();
  });

  it('should reset attempts after window expires', () => {
    const limiter = new RateLimiter({ maxAttempts: 3, windowMs: 60000 });

    // Make max attempts
    limiter.attempt();
    limiter.attempt();
    limiter.attempt();

    expect(limiter.canAttempt()).toBe(false);

    // Advance past window
    mockTime.advance(60001);

    expect(limiter.canAttempt()).toBe(true);
  });
});
```

### 4.4 Crypto Mocking

For deterministic crypto testing:

```typescript
// src/test/helpers/mock-crypto.ts
import { vi } from 'vitest';
import crypto from 'crypto';

// Known test vectors for deterministic testing
export const TEST_VECTORS = {
  // 32-byte key for AES-256
  encryptionKey: Buffer.from(
    '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
    'hex'
  ),
  // 12-byte nonce for GCM
  nonce: Buffer.from('000102030405060708090a0b', 'hex'),
  // 16-byte salt for KDF
  salt: Buffer.from('00112233445566778899aabbccddeeff', 'hex'),
};

export function createMockCrypto() {
  let nonceCounter = 0;

  const originalRandomBytes = crypto.randomBytes;

  // Mock randomBytes for deterministic nonces
  vi.spyOn(crypto, 'randomBytes').mockImplementation((size: number) => {
    if (size === 12) {
      // Nonce generation - use counter for uniqueness
      const nonce = Buffer.alloc(12);
      nonce.writeUInt32BE(nonceCounter++, 0);
      return nonce;
    }
    if (size === 16) {
      // Salt generation
      return TEST_VECTORS.salt;
    }
    // For other sizes, use real random
    return originalRandomBytes(size);
  });

  return {
    // Reset nonce counter
    resetNonce: () => {
      nonceCounter = 0;
    },

    // Get current nonce count (for verification)
    getNonceCount: () => nonceCounter,

    // Restore real crypto
    restore: () => {
      vi.restoreAllMocks();
    },

    // Test vectors
    vectors: TEST_VECTORS,
  };
}
```

---

## 5. Test Patterns by Component

### 5.1 Keystore Operations

#### 5.1.1 Encryption/Decryption Tests

```typescript
// src/keystore/local-keystore.test.ts
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { LocalFileKeystoreProvider } from './local-keystore';
import { createMockFileSystem } from '../test/helpers/mock-fs';
import { createMockCrypto, TEST_VECTORS } from '../test/helpers/mock-crypto';
import { SecureBuffer } from '../crypto/secure-buffer';

describe('LocalFileKeystoreProvider', () => {
  let mockFs: ReturnType<typeof createMockFileSystem>;
  let mockCrypto: ReturnType<typeof createMockCrypto>;
  const testDir = '/test/keystores';

  beforeEach(() => {
    mockFs = createMockFileSystem({
      [`${testDir}/.gitkeep`]: '',
    });
    mockCrypto = createMockCrypto();
  });

  afterEach(() => {
    mockFs.reset();
    mockCrypto.restore();
    vi.restoreAllMocks();
  });

  describe('createWallet', () => {
    describe('when passphrase is valid', () => {
      it('should create a new encrypted wallet file', async () => {
        const keystore = new LocalFileKeystoreProvider({
          keystorePath: testDir,
        });

        const result = await keystore.createWallet('secure-passphrase-123');

        expect(result.address).toBeValidXRPLAddress();
        expect(mockFs.fileExists(`${testDir}/${result.address}.json`)).toBe(true);
      });

      it('should use AES-256-GCM encryption', async () => {
        const keystore = new LocalFileKeystoreProvider({
          keystorePath: testDir,
        });

        const result = await keystore.createWallet('secure-passphrase-123');
        const fileContent = JSON.parse(
          mockFs.getFileContent(`${testDir}/${result.address}.json`)
        );

        expect(fileContent.encryption.algorithm).toBe('aes-256-gcm');
        expect(fileContent.encryption.kdf).toBe('argon2id');
      });

      it('should derive key using Argon2id with correct parameters', async () => {
        const keystore = new LocalFileKeystoreProvider({
          keystorePath: testDir,
        });

        const result = await keystore.createWallet('secure-passphrase-123');
        const fileContent = JSON.parse(
          mockFs.getFileContent(`${testDir}/${result.address}.json`)
        );

        expect(fileContent.encryption.kdfParams).toEqual({
          memoryCost: 65536,  // 64 MiB
          timeCost: 3,
          parallelism: 4,
          saltLength: 16,
        });
      });

      it('should include authentication tag in encrypted data', async () => {
        const keystore = new LocalFileKeystoreProvider({
          keystorePath: testDir,
        });

        const result = await keystore.createWallet('secure-passphrase-123');
        const fileContent = JSON.parse(
          mockFs.getFileContent(`${testDir}/${result.address}.json`)
        );

        // Auth tag should be 16 bytes (128 bits) in base64
        expect(fileContent.authTag).toBeDefined();
        expect(Buffer.from(fileContent.authTag, 'base64').length).toBe(16);
      });
    });

    describe('when passphrase is invalid', () => {
      it('should throw error for empty passphrase', async () => {
        const keystore = new LocalFileKeystoreProvider({
          keystorePath: testDir,
        });

        await expect(keystore.createWallet('')).rejects.toThrow(
          'Passphrase must be at least 8 characters'
        );
      });

      it('should throw error for passphrase shorter than 8 characters', async () => {
        const keystore = new LocalFileKeystoreProvider({
          keystorePath: testDir,
        });

        await expect(keystore.createWallet('short')).rejects.toThrow(
          'Passphrase must be at least 8 characters'
        );
      });
    });
  });

  describe('unlockWallet', () => {
    const testAddress = 'rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh';
    const testPassphrase = 'correct-passphrase-123';

    beforeEach(async () => {
      // Create a wallet first
      const keystore = new LocalFileKeystoreProvider({
        keystorePath: testDir,
      });
      await keystore.createWallet(testPassphrase);
    });

    it('should decrypt wallet with correct passphrase', async () => {
      const keystore = new LocalFileKeystoreProvider({
        keystorePath: testDir,
      });

      const wallet = await keystore.unlockWallet(testAddress, testPassphrase);

      expect(wallet.address).toBe(testAddress);
      expect(wallet.privateKey).toBeDefined();
    });

    it('should return SecureBuffer for private key', async () => {
      const keystore = new LocalFileKeystoreProvider({
        keystorePath: testDir,
      });

      const wallet = await keystore.unlockWallet(testAddress, testPassphrase);

      expect(wallet.privateKey).toBeInstanceOf(SecureBuffer);
    });

    it('should throw error with incorrect passphrase', async () => {
      const keystore = new LocalFileKeystoreProvider({
        keystorePath: testDir,
      });

      await expect(
        keystore.unlockWallet(testAddress, 'wrong-passphrase')
      ).rejects.toThrow('Invalid passphrase or corrupted wallet');
    });

    it('should throw error for non-existent wallet', async () => {
      const keystore = new LocalFileKeystoreProvider({
        keystorePath: testDir,
      });

      await expect(
        keystore.unlockWallet('rNonExistent123456789012345', testPassphrase)
      ).rejects.toThrow('Wallet not found');
    });
  });

  describe('SecureBuffer handling', () => {
    it('should clear sensitive data from memory after use', async () => {
      const keystore = new LocalFileKeystoreProvider({
        keystorePath: testDir,
      });

      await keystore.createWallet('secure-passphrase-123');
      const wallet = await keystore.unlockWallet(
        keystore.listWallets()[0],
        'secure-passphrase-123'
      );

      // Get reference to internal buffer
      const privateKeyBuffer = wallet.privateKey.getBuffer();

      // Clear the SecureBuffer
      wallet.privateKey.clear();

      // Verify buffer is zeroed
      expect(privateKeyBuffer).toBeSecurelyCleared();
    });
  });
});
```

#### 5.1.2 File I/O Tests

```typescript
describe('LocalFileKeystoreProvider', () => {
  describe('file operations', () => {
    describe('atomic writes', () => {
      it('should write to temp file then rename', async () => {
        const keystore = new LocalFileKeystoreProvider({
          keystorePath: testDir,
        });
        const renameSpy = vi.spyOn(fs.promises, 'rename');

        await keystore.createWallet('passphrase-123');

        expect(renameSpy).toHaveBeenCalledWith(
          expect.stringContaining('.tmp'),
          expect.not.stringContaining('.tmp')
        );
      });

      it('should clean up temp file on error', async () => {
        const keystore = new LocalFileKeystoreProvider({
          keystorePath: testDir,
        });

        // Force rename to fail
        vi.spyOn(fs.promises, 'rename').mockRejectedValueOnce(
          new Error('Rename failed')
        );

        await expect(keystore.createWallet('passphrase-123')).rejects.toThrow();

        // Temp file should be cleaned up
        const files = mockFs.vol.readdirSync(testDir);
        expect(files.some((f: string) => f.endsWith('.tmp'))).toBe(false);
      });
    });

    describe('file permissions', () => {
      it('should create wallet file with restricted permissions', async () => {
        const keystore = new LocalFileKeystoreProvider({
          keystorePath: testDir,
        });
        const chmodSpy = vi.spyOn(fs.promises, 'chmod');

        await keystore.createWallet('passphrase-123');

        expect(chmodSpy).toHaveBeenCalledWith(
          expect.any(String),
          0o600  // Owner read/write only
        );
      });
    });

    describe('backup operations', () => {
      it('should create backup before updating wallet', async () => {
        const keystore = new LocalFileKeystoreProvider({
          keystorePath: testDir,
          backup: { enabled: true, maxBackups: 3 },
        });

        const address = (await keystore.createWallet('passphrase-123')).address;
        await keystore.updateWallet(address, { name: 'Updated' });

        expect(mockFs.fileExists(`${testDir}/backups/${address}.json.1`)).toBe(true);
      });

      it('should rotate backups when max reached', async () => {
        const keystore = new LocalFileKeystoreProvider({
          keystorePath: testDir,
          backup: { enabled: true, maxBackups: 2 },
        });

        const address = (await keystore.createWallet('passphrase-123')).address;

        // Create multiple updates
        await keystore.updateWallet(address, { name: 'Update 1' });
        await keystore.updateWallet(address, { name: 'Update 2' });
        await keystore.updateWallet(address, { name: 'Update 3' });

        // Should only have 2 backups
        expect(mockFs.fileExists(`${testDir}/backups/${address}.json.1`)).toBe(true);
        expect(mockFs.fileExists(`${testDir}/backups/${address}.json.2`)).toBe(true);
        expect(mockFs.fileExists(`${testDir}/backups/${address}.json.3`)).toBe(false);
      });
    });
  });
});
```

### 5.2 Policy Engine

```typescript
// src/policy/policy-engine.test.ts
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { PolicyEngine } from './policy-engine';
import { TierClassifier } from './tier-classifier';
import { createMockTime } from '../test/helpers/mock-time';

describe('PolicyEngine', () => {
  let mockTime: ReturnType<typeof createMockTime>;

  beforeEach(() => {
    mockTime = createMockTime({
      initialTime: new Date('2026-01-28T12:00:00Z'),
    });
  });

  afterEach(() => {
    mockTime.restore();
  });

  describe('TierClassifier', () => {
    describe('classifyTransaction', () => {
      it('should classify small XRP transfers as Tier 1', () => {
        const classifier = new TierClassifier({
          tier1MaxXrp: 100,
          tier2MaxXrp: 1000,
        });

        const tier = classifier.classifyTransaction({
          type: 'Payment',
          amount: { currency: 'XRP', value: '50' },
        });

        expect(tier).toBe(1);
      });

      it('should classify medium XRP transfers as Tier 2', () => {
        const classifier = new TierClassifier({
          tier1MaxXrp: 100,
          tier2MaxXrp: 1000,
        });

        const tier = classifier.classifyTransaction({
          type: 'Payment',
          amount: { currency: 'XRP', value: '500' },
        });

        expect(tier).toBe(2);
      });

      it('should classify large XRP transfers as Tier 3', () => {
        const classifier = new TierClassifier({
          tier1MaxXrp: 100,
          tier2MaxXrp: 1000,
        });

        const tier = classifier.classifyTransaction({
          type: 'Payment',
          amount: { currency: 'XRP', value: '5000' },
        });

        expect(tier).toBe(3);
      });

      it('should classify token transfers based on configured limits', () => {
        const classifier = new TierClassifier({
          tier1MaxXrp: 100,
          tier2MaxXrp: 1000,
          tokenLimits: {
            USD: { tier1: 100, tier2: 1000 },
          },
        });

        const tier = classifier.classifyTransaction({
          type: 'Payment',
          amount: {
            currency: 'USD',
            issuer: 'rIssuer123',
            value: '500',
          },
        });

        expect(tier).toBe(2);
      });

      it('should classify unknown tokens as Tier 3', () => {
        const classifier = new TierClassifier({
          tier1MaxXrp: 100,
          tier2MaxXrp: 1000,
        });

        const tier = classifier.classifyTransaction({
          type: 'Payment',
          amount: {
            currency: 'UNKNOWN',
            issuer: 'rIssuer123',
            value: '1',
          },
        });

        expect(tier).toBe(3);
      });

      it('should classify AccountSet as Tier 2', () => {
        const classifier = new TierClassifier({});

        const tier = classifier.classifyTransaction({
          type: 'AccountSet',
          setFlag: 8, // asfDefaultRipple
        });

        expect(tier).toBe(2);
      });

      it('should classify SetRegularKey as Tier 3', () => {
        const classifier = new TierClassifier({});

        const tier = classifier.classifyTransaction({
          type: 'SetRegularKey',
          regularKey: 'rNewKey123',
        });

        expect(tier).toBe(3);
      });

      it('should classify SignerListSet as Tier 3', () => {
        const classifier = new TierClassifier({});

        const tier = classifier.classifyTransaction({
          type: 'SignerListSet',
          signerQuorum: 2,
          signerEntries: [],
        });

        expect(tier).toBe(3);
      });
    });
  });

  describe('evaluatePolicy', () => {
    it('should approve Tier 1 transaction within limits', async () => {
      const engine = new PolicyEngine({
        limits: {
          tier1: { maxPerTransaction: 100, maxPerDay: 500 },
        },
      });

      const result = await engine.evaluatePolicy({
        transaction: {
          type: 'Payment',
          amount: { currency: 'XRP', value: '50' },
        },
        wallet: 'rWallet123',
      });

      expect(result.approved).toBe(true);
      expect(result.tier).toBe(1);
      expect(result.requiresMultiSig).toBe(false);
    });

    it('should require approval for Tier 2 transactions', async () => {
      const engine = new PolicyEngine({
        limits: {
          tier1: { maxPerTransaction: 100 },
          tier2: { maxPerTransaction: 1000, requiresApproval: true },
        },
      });

      const result = await engine.evaluatePolicy({
        transaction: {
          type: 'Payment',
          amount: { currency: 'XRP', value: '500' },
        },
        wallet: 'rWallet123',
      });

      expect(result.approved).toBe(false);
      expect(result.tier).toBe(2);
      expect(result.requiresApproval).toBe(true);
    });

    it('should require multi-sig for Tier 3 transactions', async () => {
      const engine = new PolicyEngine({
        limits: {
          tier3: { requiresMultiSig: true, minSignatures: 2 },
        },
      });

      const result = await engine.evaluatePolicy({
        transaction: {
          type: 'Payment',
          amount: { currency: 'XRP', value: '5000' },
        },
        wallet: 'rWallet123',
      });

      expect(result.approved).toBe(false);
      expect(result.tier).toBe(3);
      expect(result.requiresMultiSig).toBe(true);
      expect(result.minSignatures).toBe(2);
    });
  });

  describe('limit tracking', () => {
    it('should track daily spending', async () => {
      const engine = new PolicyEngine({
        limits: {
          tier1: { maxPerDay: 200 },
        },
      });

      // First transaction
      await engine.evaluatePolicy({
        transaction: {
          type: 'Payment',
          amount: { currency: 'XRP', value: '100' },
        },
        wallet: 'rWallet123',
      });
      await engine.recordTransaction('rWallet123', 100);

      // Second transaction should work
      const result1 = await engine.evaluatePolicy({
        transaction: {
          type: 'Payment',
          amount: { currency: 'XRP', value: '99' },
        },
        wallet: 'rWallet123',
      });
      expect(result1.approved).toBe(true);

      // Third transaction should fail (exceeds daily limit)
      const result2 = await engine.evaluatePolicy({
        transaction: {
          type: 'Payment',
          amount: { currency: 'XRP', value: '50' },
        },
        wallet: 'rWallet123',
      });
      expect(result2.approved).toBe(false);
      expect(result2.reason).toContain('Daily limit exceeded');
    });

    it('should reset daily limits at midnight UTC', async () => {
      const engine = new PolicyEngine({
        limits: {
          tier1: { maxPerDay: 200 },
        },
      });

      // Max out daily limit
      await engine.recordTransaction('rWallet123', 200);

      const result1 = await engine.evaluatePolicy({
        transaction: {
          type: 'Payment',
          amount: { currency: 'XRP', value: '50' },
        },
        wallet: 'rWallet123',
      });
      expect(result1.approved).toBe(false);

      // Advance to next day
      mockTime.advanceTo(new Date('2026-01-29T00:00:01Z'));

      const result2 = await engine.evaluatePolicy({
        transaction: {
          type: 'Payment',
          amount: { currency: 'XRP', value: '50' },
        },
        wallet: 'rWallet123',
      });
      expect(result2.approved).toBe(true);
    });

    it('should track per-wallet limits separately', async () => {
      const engine = new PolicyEngine({
        limits: {
          tier1: { maxPerDay: 200 },
        },
      });

      // Max out wallet 1
      await engine.recordTransaction('rWallet1', 200);

      // Wallet 2 should still work
      const result = await engine.evaluatePolicy({
        transaction: {
          type: 'Payment',
          amount: { currency: 'XRP', value: '100' },
        },
        wallet: 'rWallet2',
      });
      expect(result.approved).toBe(true);
    });
  });
});
```

### 5.3 Audit Logger

```typescript
// src/audit/audit-logger.test.ts
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { AuditLogger, AuditEvent } from './audit-logger';
import { createMockFileSystem } from '../test/helpers/mock-fs';
import { createMockTime } from '../test/helpers/mock-time';
import crypto from 'crypto';

describe('AuditLogger', () => {
  let mockFs: ReturnType<typeof createMockFileSystem>;
  let mockTime: ReturnType<typeof createMockTime>;
  const auditDir = '/test/audit';

  beforeEach(() => {
    mockFs = createMockFileSystem({
      [`${auditDir}/.gitkeep`]: '',
    });
    mockTime = createMockTime({
      initialTime: new Date('2026-01-28T12:00:00Z'),
    });
  });

  afterEach(() => {
    mockFs.reset();
    mockTime.restore();
    vi.restoreAllMocks();
  });

  describe('logEvent', () => {
    it('should log event with timestamp', async () => {
      const logger = new AuditLogger({ auditPath: auditDir });

      await logger.logEvent({
        type: 'WALLET_CREATED',
        walletAddress: 'rWallet123',
        details: { name: 'Test Wallet' },
      });

      const events = await logger.getEvents();
      expect(events).toHaveLength(1);
      expect(events[0].timestamp).toBe('2026-01-28T12:00:00.000Z');
    });

    it('should include event type and details', async () => {
      const logger = new AuditLogger({ auditPath: auditDir });

      await logger.logEvent({
        type: 'TRANSACTION_SIGNED',
        walletAddress: 'rWallet123',
        details: {
          txHash: 'ABC123',
          amount: '100',
          destination: 'rDest456',
        },
      });

      const events = await logger.getEvents();
      expect(events[0].type).toBe('TRANSACTION_SIGNED');
      expect(events[0].details.txHash).toBe('ABC123');
    });

    it('should sanitize sensitive data', async () => {
      const logger = new AuditLogger({ auditPath: auditDir });

      await logger.logEvent({
        type: 'WALLET_UNLOCKED',
        walletAddress: 'rWallet123',
        details: {
          passphrase: 'secret-passphrase',  // Should be redacted
          publicKey: 'ED123...',
        },
      });

      const events = await logger.getEvents();
      expect(events[0].details.passphrase).toBe('[REDACTED]');
      expect(events[0].details.publicKey).toBe('ED123...');
    });
  });

  describe('hash chain integrity', () => {
    it('should include previous event hash in new events', async () => {
      const logger = new AuditLogger({ auditPath: auditDir });

      await logger.logEvent({
        type: 'WALLET_CREATED',
        walletAddress: 'rWallet123',
      });

      mockTime.advance(1000);

      await logger.logEvent({
        type: 'WALLET_UNLOCKED',
        walletAddress: 'rWallet123',
      });

      const events = await logger.getEvents();
      expect(events[0].previousHash).toBeNull();
      expect(events[1].previousHash).toBe(events[0].hash);
    });

    it('should calculate hash correctly', async () => {
      const logger = new AuditLogger({ auditPath: auditDir });

      await logger.logEvent({
        type: 'WALLET_CREATED',
        walletAddress: 'rWallet123',
        details: { name: 'Test' },
      });

      const events = await logger.getEvents();
      const event = events[0];

      // Calculate expected hash
      const hashInput = JSON.stringify({
        timestamp: event.timestamp,
        type: event.type,
        walletAddress: event.walletAddress,
        details: event.details,
        previousHash: event.previousHash,
      });
      const expectedHash = crypto
        .createHash('sha256')
        .update(hashInput)
        .digest('hex');

      expect(event.hash).toBe(expectedHash);
    });

    it('should detect tampering in hash chain', async () => {
      const logger = new AuditLogger({ auditPath: auditDir });

      // Create several events
      await logger.logEvent({ type: 'EVENT_1', walletAddress: 'rWallet' });
      mockTime.advance(1000);
      await logger.logEvent({ type: 'EVENT_2', walletAddress: 'rWallet' });
      mockTime.advance(1000);
      await logger.logEvent({ type: 'EVENT_3', walletAddress: 'rWallet' });

      // Tamper with middle event
      const auditFile = `${auditDir}/audit.log`;
      const content = JSON.parse(mockFs.getFileContent(auditFile));
      content[1].details = { tampered: true };
      mockFs.vol.writeFileSync(auditFile, JSON.stringify(content));

      // Verification should fail
      const validation = await logger.verifyIntegrity();
      expect(validation.valid).toBe(false);
      expect(validation.error).toContain('Hash mismatch');
      expect(validation.errorIndex).toBe(1);
    });

    it('should detect deleted events in chain', async () => {
      const logger = new AuditLogger({ auditPath: auditDir });

      await logger.logEvent({ type: 'EVENT_1', walletAddress: 'rWallet' });
      mockTime.advance(1000);
      await logger.logEvent({ type: 'EVENT_2', walletAddress: 'rWallet' });
      mockTime.advance(1000);
      await logger.logEvent({ type: 'EVENT_3', walletAddress: 'rWallet' });

      // Delete middle event
      const auditFile = `${auditDir}/audit.log`;
      const content = JSON.parse(mockFs.getFileContent(auditFile));
      content.splice(1, 1);  // Remove middle event
      mockFs.vol.writeFileSync(auditFile, JSON.stringify(content));

      const validation = await logger.verifyIntegrity();
      expect(validation.valid).toBe(false);
      expect(validation.error).toContain('Chain broken');
    });
  });

  describe('event querying', () => {
    beforeEach(async () => {
      const logger = new AuditLogger({ auditPath: auditDir });

      await logger.logEvent({
        type: 'WALLET_CREATED',
        walletAddress: 'rWallet1',
      });
      mockTime.advance(3600000); // 1 hour

      await logger.logEvent({
        type: 'TRANSACTION_SIGNED',
        walletAddress: 'rWallet1',
      });
      mockTime.advance(3600000);

      await logger.logEvent({
        type: 'WALLET_CREATED',
        walletAddress: 'rWallet2',
      });
    });

    it('should filter events by type', async () => {
      const logger = new AuditLogger({ auditPath: auditDir });

      const events = await logger.getEvents({
        type: 'WALLET_CREATED',
      });

      expect(events).toHaveLength(2);
      expect(events.every(e => e.type === 'WALLET_CREATED')).toBe(true);
    });

    it('should filter events by wallet', async () => {
      const logger = new AuditLogger({ auditPath: auditDir });

      const events = await logger.getEvents({
        walletAddress: 'rWallet1',
      });

      expect(events).toHaveLength(2);
      expect(events.every(e => e.walletAddress === 'rWallet1')).toBe(true);
    });

    it('should filter events by time range', async () => {
      const logger = new AuditLogger({ auditPath: auditDir });

      const events = await logger.getEvents({
        startTime: new Date('2026-01-28T12:30:00Z'),
        endTime: new Date('2026-01-28T13:30:00Z'),
      });

      expect(events).toHaveLength(1);
      expect(events[0].type).toBe('TRANSACTION_SIGNED');
    });
  });
});
```

### 5.4 Input Validators

```typescript
// src/validators/schemas.test.ts
import { describe, it, expect } from 'vitest';
import { z } from 'zod';
import {
  xrplAddressSchema,
  xrplAmountSchema,
  transactionRequestSchema,
  walletConfigSchema,
  policyConfigSchema,
  passphraseSchema,
} from './schemas';

describe('Validators', () => {
  describe('xrplAddressSchema', () => {
    it('should accept valid classic address', () => {
      const result = xrplAddressSchema.safeParse('rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh');
      expect(result.success).toBe(true);
    });

    it('should accept valid X-address', () => {
      const result = xrplAddressSchema.safeParse(
        'X7gJ5YK8abHf2eTPWPFHAAot8Knck11QGqmQ7a6a3Z8PJvk'
      );
      expect(result.success).toBe(true);
    });

    it('should reject address not starting with r or X', () => {
      const result = xrplAddressSchema.safeParse('sHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh');
      expect(result.success).toBe(false);
      expect(result.error?.issues[0].message).toContain('Invalid XRPL address');
    });

    it('should reject address with invalid characters', () => {
      const result = xrplAddressSchema.safeParse('rHb9CJAWyB4rj91VRWn96DkukG4bwdty0O');
      expect(result.success).toBe(false);
    });

    it('should reject address that is too short', () => {
      const result = xrplAddressSchema.safeParse('rHb9CJAWyB4rj91VRW');
      expect(result.success).toBe(false);
    });

    it('should reject address that is too long', () => {
      const result = xrplAddressSchema.safeParse(
        'rHb9CJAWyB4rj91VRWn96DkukG4bwdtyThExtraChars123456'
      );
      expect(result.success).toBe(false);
    });
  });

  describe('xrplAmountSchema', () => {
    describe('XRP amounts', () => {
      it('should accept valid drops string', () => {
        const result = xrplAmountSchema.safeParse('1000000');
        expect(result.success).toBe(true);
      });

      it('should reject negative amounts', () => {
        const result = xrplAmountSchema.safeParse('-1000000');
        expect(result.success).toBe(false);
      });

      it('should reject non-numeric strings', () => {
        const result = xrplAmountSchema.safeParse('abc');
        expect(result.success).toBe(false);
      });

      it('should reject amounts exceeding max XRP', () => {
        // Max XRP is 100 billion = 100e18 drops
        const result = xrplAmountSchema.safeParse('100000000000000000001');
        expect(result.success).toBe(false);
      });
    });

    describe('token amounts', () => {
      it('should accept valid issued currency', () => {
        const result = xrplAmountSchema.safeParse({
          currency: 'USD',
          issuer: 'rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh',
          value: '100.50',
        });
        expect(result.success).toBe(true);
      });

      it('should accept 40-character hex currency code', () => {
        const result = xrplAmountSchema.safeParse({
          currency: '0000000000000000000000005553440000000000',
          issuer: 'rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh',
          value: '100',
        });
        expect(result.success).toBe(true);
      });

      it('should reject XRP as issued currency', () => {
        const result = xrplAmountSchema.safeParse({
          currency: 'XRP',
          issuer: 'rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh',
          value: '100',
        });
        expect(result.success).toBe(false);
        expect(result.error?.issues[0].message).toContain('XRP cannot have issuer');
      });

      it('should reject missing issuer for token', () => {
        const result = xrplAmountSchema.safeParse({
          currency: 'USD',
          value: '100',
        });
        expect(result.success).toBe(false);
      });

      it('should reject invalid issuer address', () => {
        const result = xrplAmountSchema.safeParse({
          currency: 'USD',
          issuer: 'invalid-address',
          value: '100',
        });
        expect(result.success).toBe(false);
      });

      it('should handle scientific notation', () => {
        const result = xrplAmountSchema.safeParse({
          currency: 'USD',
          issuer: 'rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh',
          value: '1e10',
        });
        expect(result.success).toBe(true);
      });
    });
  });

  describe('transactionRequestSchema', () => {
    it('should accept valid Payment transaction', () => {
      const result = transactionRequestSchema.safeParse({
        type: 'Payment',
        destination: 'rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh',
        amount: '1000000',
      });
      expect(result.success).toBe(true);
    });

    it('should accept valid TrustSet transaction', () => {
      const result = transactionRequestSchema.safeParse({
        type: 'TrustSet',
        limitAmount: {
          currency: 'USD',
          issuer: 'rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh',
          value: '1000000',
        },
      });
      expect(result.success).toBe(true);
    });

    it('should accept valid AccountSet transaction', () => {
      const result = transactionRequestSchema.safeParse({
        type: 'AccountSet',
        setFlag: 8,  // asfDefaultRipple
      });
      expect(result.success).toBe(true);
    });

    it('should reject unknown transaction type', () => {
      const result = transactionRequestSchema.safeParse({
        type: 'UnknownType',
        data: 'something',
      });
      expect(result.success).toBe(false);
    });

    it('should reject Payment without destination', () => {
      const result = transactionRequestSchema.safeParse({
        type: 'Payment',
        amount: '1000000',
      });
      expect(result.success).toBe(false);
    });
  });

  describe('passphraseSchema', () => {
    it('should accept passphrase with 8+ characters', () => {
      const result = passphraseSchema.safeParse('secure-pass-123');
      expect(result.success).toBe(true);
    });

    it('should reject passphrase shorter than 8 characters', () => {
      const result = passphraseSchema.safeParse('short');
      expect(result.success).toBe(false);
      expect(result.error?.issues[0].message).toContain('at least 8 characters');
    });

    it('should reject empty passphrase', () => {
      const result = passphraseSchema.safeParse('');
      expect(result.success).toBe(false);
    });

    it('should reject null or undefined', () => {
      expect(passphraseSchema.safeParse(null).success).toBe(false);
      expect(passphraseSchema.safeParse(undefined).success).toBe(false);
    });

    it('should handle unicode characters', () => {
      const result = passphraseSchema.safeParse('p@sswrd123');
      expect(result.success).toBe(true);
    });
  });

  describe('policyConfigSchema', () => {
    it('should accept valid policy configuration', () => {
      const result = policyConfigSchema.safeParse({
        limits: {
          tier1: {
            maxPerTransaction: 100,
            maxPerDay: 500,
          },
          tier2: {
            maxPerTransaction: 1000,
            requiresApproval: true,
          },
          tier3: {
            requiresMultiSig: true,
            minSignatures: 2,
          },
        },
      });
      expect(result.success).toBe(true);
    });

    it('should apply defaults for missing fields', () => {
      const result = policyConfigSchema.safeParse({});
      expect(result.success).toBe(true);
      expect(result.data?.limits?.tier1?.maxPerTransaction).toBeDefined();
    });

    it('should reject negative limit values', () => {
      const result = policyConfigSchema.safeParse({
        limits: {
          tier1: {
            maxPerTransaction: -100,
          },
        },
      });
      expect(result.success).toBe(false);
    });
  });
});
```

### 5.5 XRPL Client

```typescript
// src/xrpl/xrpl-client.test.ts
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { XRPLClient } from './xrpl-client';
import { createMockXRPLClient, createMockWallet } from '../test/helpers/mock-xrpl';
import { createMockTime } from '../test/helpers/mock-time';

describe('XRPLClient', () => {
  let mockXrpl: ReturnType<typeof createMockXRPLClient>;
  let mockTime: ReturnType<typeof createMockTime>;

  beforeEach(() => {
    mockXrpl = createMockXRPLClient();
    mockTime = createMockTime();
  });

  afterEach(() => {
    mockXrpl.reset();
    mockTime.restore();
    vi.restoreAllMocks();
  });

  describe('connection management', () => {
    describe('connect', () => {
      it('should establish WebSocket connection', async () => {
        const client = new XRPLClient({
          serverUrl: 'wss://testnet.xrpl.org',
        });

        await client.connect();

        expect(mockXrpl.client.connect).toHaveBeenCalled();
        expect(client.isConnected()).toBe(true);
      });

      it('should validate network on connection', async () => {
        const client = new XRPLClient({
          serverUrl: 'wss://testnet.xrpl.org',
          expectedNetworkId: 1,
        });

        await client.connect();

        expect(mockXrpl.client.request).toHaveBeenCalledWith({
          command: 'server_info',
        });
      });

      it('should reject connection to wrong network', async () => {
        mockXrpl.client.request.mockImplementation(async (req: { command: string }) => {
          if (req.command === 'server_info') {
            return { result: { info: { network_id: 999 } } };
          }
          return { result: {} };
        });

        const client = new XRPLClient({
          serverUrl: 'wss://testnet.xrpl.org',
          expectedNetworkId: 1,
        });

        await expect(client.connect()).rejects.toThrow('Network mismatch');
      });
    });

    describe('reconnection', () => {
      it('should reconnect on disconnect with exponential backoff', async () => {
        const client = new XRPLClient({
          serverUrl: 'wss://testnet.xrpl.org',
          reconnect: {
            enabled: true,
            maxAttempts: 3,
            baseDelayMs: 1000,
            maxDelayMs: 30000,
          },
        });

        await client.connect();

        // Simulate disconnect
        mockXrpl.setConnected(false);
        mockXrpl.simulateDisconnect();

        // First reconnect attempt
        mockTime.advance(1000);
        mockTime.runPending();

        expect(mockXrpl.client.connect).toHaveBeenCalledTimes(2);

        // Second attempt with exponential backoff
        mockTime.advance(2000);
        mockTime.runPending();

        expect(mockXrpl.client.connect).toHaveBeenCalledTimes(3);
      });

      it('should stop reconnecting after max attempts', async () => {
        mockXrpl.client.connect
          .mockRejectedValueOnce(new Error('Connection failed'))
          .mockRejectedValueOnce(new Error('Connection failed'))
          .mockRejectedValue(new Error('Connection failed'));

        const client = new XRPLClient({
          serverUrl: 'wss://testnet.xrpl.org',
          reconnect: {
            enabled: true,
            maxAttempts: 3,
          },
        });

        await expect(client.connect()).rejects.toThrow();

        mockTime.runAll();

        // Should not attempt more than max
        expect(mockXrpl.client.connect).toHaveBeenCalledTimes(3);
      });
    });

    describe('health check', () => {
      it('should perform health check on interval', async () => {
        const client = new XRPLClient({
          serverUrl: 'wss://testnet.xrpl.org',
          healthCheck: {
            enabled: true,
            intervalMs: 30000,
          },
        });

        await client.connect();

        // Initial request count
        const initialCount = mockXrpl.client.request.mock.calls.length;

        // Advance to health check time
        mockTime.advance(30000);
        mockTime.runPending();

        expect(mockXrpl.client.request.mock.calls.length).toBeGreaterThan(initialCount);
      });
    });
  });

  describe('account operations', () => {
    beforeEach(async () => {
      const client = new XRPLClient({ serverUrl: 'wss://testnet.xrpl.org' });
      await client.connect();
    });

    describe('getBalance', () => {
      it('should return account balance in XRP', async () => {
        mockXrpl.setAccountBalance('50000000'); // 50 XRP in drops

        const client = new XRPLClient({ serverUrl: 'wss://testnet.xrpl.org' });
        await client.connect();

        const balance = await client.getBalance('rWallet123');

        expect(balance.xrp).toBe('50');
        expect(balance.drops).toBe('50000000');
      });

      it('should throw AccountNotFoundError for unknown account', async () => {
        mockXrpl.client.request.mockRejectedValueOnce({
          data: { error: 'actNotFound' },
        });

        const client = new XRPLClient({ serverUrl: 'wss://testnet.xrpl.org' });
        await client.connect();

        await expect(client.getBalance('rUnknown123')).rejects.toThrow(
          'AccountNotFoundError'
        );
      });
    });

    describe('getAccountInfo', () => {
      it('should return full account info', async () => {
        mockXrpl.client.request.mockResolvedValueOnce({
          result: {
            account_data: {
              Account: 'rWallet123',
              Balance: '50000000',
              Sequence: 10,
              Flags: 0,
            },
          },
        });

        const client = new XRPLClient({ serverUrl: 'wss://testnet.xrpl.org' });
        await client.connect();

        const info = await client.getAccountInfo('rWallet123');

        expect(info.address).toBe('rWallet123');
        expect(info.sequence).toBe(10);
      });
    });
  });

  describe('transaction operations', () => {
    describe('signTransaction', () => {
      it('should sign transaction with wallet', async () => {
        const client = new XRPLClient({ serverUrl: 'wss://testnet.xrpl.org' });
        await client.connect();

        const wallet = createMockWallet();
        const tx = {
          TransactionType: 'Payment',
          Account: wallet.address,
          Destination: 'rDest123',
          Amount: '1000000',
        };

        const signed = await client.signTransaction(tx, wallet);

        expect(signed.tx_blob).toBeDefined();
        expect(signed.hash).toBeDefined();
      });
    });

    describe('submitTransaction', () => {
      it('should submit signed transaction', async () => {
        mockXrpl.setSubmitResponse({
          result: {
            engine_result: 'tesSUCCESS',
            engine_result_code: 0,
            tx_json: { hash: 'TX_HASH_123' },
          },
        });

        const client = new XRPLClient({ serverUrl: 'wss://testnet.xrpl.org' });
        await client.connect();

        const result = await client.submitTransaction('signed_tx_blob');

        expect(result.success).toBe(true);
        expect(result.hash).toBe('TX_HASH_123');
      });

      it('should handle transaction failure', async () => {
        mockXrpl.setSubmitResponse({
          result: {
            engine_result: 'tecUNFUNDED_PAYMENT',
            engine_result_code: 104,
            engine_result_message: 'Insufficient XRP balance',
          },
        });

        const client = new XRPLClient({ serverUrl: 'wss://testnet.xrpl.org' });
        await client.connect();

        const result = await client.submitTransaction('signed_tx_blob');

        expect(result.success).toBe(false);
        expect(result.error).toContain('Insufficient XRP balance');
      });

      it('should throw on network error', async () => {
        mockXrpl.setSubmitError(new Error('Network error'));

        const client = new XRPLClient({ serverUrl: 'wss://testnet.xrpl.org' });
        await client.connect();

        await expect(client.submitTransaction('signed_tx_blob')).rejects.toThrow(
          'Network error'
        );
      });
    });

    describe('autofill', () => {
      it('should autofill Fee, Sequence, and LastLedgerSequence', async () => {
        const client = new XRPLClient({ serverUrl: 'wss://testnet.xrpl.org' });
        await client.connect();

        const tx = {
          TransactionType: 'Payment',
          Account: 'rWallet123',
          Destination: 'rDest456',
          Amount: '1000000',
        };

        const filled = await client.autofill(tx);

        expect(filled.Fee).toBeDefined();
        expect(filled.Sequence).toBeDefined();
        expect(filled.LastLedgerSequence).toBeDefined();
      });
    });
  });

  describe('error handling', () => {
    it('should wrap XRPL errors with context', async () => {
      mockXrpl.client.request.mockRejectedValueOnce({
        data: {
          error: 'invalidParams',
          error_message: 'Missing required field',
        },
      });

      const client = new XRPLClient({ serverUrl: 'wss://testnet.xrpl.org' });
      await client.connect();

      try {
        await client.getAccountInfo('invalid');
        expect.fail('Should have thrown');
      } catch (error) {
        expect(error.code).toBe('XRPL_ERROR');
        expect(error.originalError).toBeDefined();
      }
    });

    it('should handle connection timeout', async () => {
      mockXrpl.client.connect.mockImplementation(
        () => new Promise((_, reject) => {
          setTimeout(() => reject(new Error('Timeout')), 10000);
        })
      );

      const client = new XRPLClient({
        serverUrl: 'wss://testnet.xrpl.org',
        connectionTimeout: 5000,
      });

      mockTime.advance(6000);

      await expect(client.connect()).rejects.toThrow('Timeout');
    });
  });
});
```

### 5.6 Multi-Sign Orchestrator

```typescript
// src/multisig/orchestrator.test.ts
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { MultiSignOrchestrator } from './orchestrator';
import { createMockFileSystem } from '../test/helpers/mock-fs';
import { createMockTime } from '../test/helpers/mock-time';
import { createMockXRPLClient } from '../test/helpers/mock-xrpl';

describe('MultiSignOrchestrator', () => {
  let mockFs: ReturnType<typeof createMockFileSystem>;
  let mockTime: ReturnType<typeof createMockTime>;
  let mockXrpl: ReturnType<typeof createMockXRPLClient>;

  beforeEach(() => {
    mockFs = createMockFileSystem();
    mockTime = createMockTime({
      initialTime: new Date('2026-01-28T12:00:00Z'),
    });
    mockXrpl = createMockXRPLClient();
  });

  afterEach(() => {
    mockFs.reset();
    mockTime.restore();
    mockXrpl.reset();
    vi.restoreAllMocks();
  });

  describe('createMultiSignRequest', () => {
    it('should create pending multi-sign request', async () => {
      const orchestrator = new MultiSignOrchestrator({
        storePath: '/test/multisig',
        signerList: {
          quorum: 2,
          signers: [
            { address: 'rSigner1', weight: 1 },
            { address: 'rSigner2', weight: 1 },
            { address: 'rSigner3', weight: 1 },
          ],
        },
      });

      const request = await orchestrator.createRequest({
        transaction: {
          TransactionType: 'Payment',
          Account: 'rMultiSigWallet',
          Destination: 'rDest123',
          Amount: '5000000000', // 5000 XRP - Tier 3
        },
        initiator: 'rSigner1',
      });

      expect(request.id).toBeDefined();
      expect(request.status).toBe('pending');
      expect(request.signatures).toHaveLength(0);
      expect(request.quorumMet).toBe(false);
    });

    it('should set expiration time', async () => {
      const orchestrator = new MultiSignOrchestrator({
        storePath: '/test/multisig',
        signerList: {
          quorum: 2,
          signers: [
            { address: 'rSigner1', weight: 1 },
            { address: 'rSigner2', weight: 1 },
          ],
        },
        expirationMs: 3600000, // 1 hour
      });

      const request = await orchestrator.createRequest({
        transaction: {
          TransactionType: 'Payment',
          Account: 'rMultiSigWallet',
          Destination: 'rDest123',
          Amount: '5000000000',
        },
        initiator: 'rSigner1',
      });

      expect(request.expiresAt).toBe('2026-01-28T13:00:00.000Z');
    });
  });

  describe('addSignature', () => {
    let requestId: string;

    beforeEach(async () => {
      const orchestrator = new MultiSignOrchestrator({
        storePath: '/test/multisig',
        signerList: {
          quorum: 2,
          signers: [
            { address: 'rSigner1', weight: 1 },
            { address: 'rSigner2', weight: 1 },
            { address: 'rSigner3', weight: 1 },
          ],
        },
      });

      const request = await orchestrator.createRequest({
        transaction: {
          TransactionType: 'Payment',
          Account: 'rMultiSigWallet',
          Destination: 'rDest123',
          Amount: '5000000000',
        },
        initiator: 'rSigner1',
      });

      requestId = request.id;
    });

    it('should add valid signature from authorized signer', async () => {
      const orchestrator = new MultiSignOrchestrator({
        storePath: '/test/multisig',
        signerList: {
          quorum: 2,
          signers: [
            { address: 'rSigner1', weight: 1 },
            { address: 'rSigner2', weight: 1 },
            { address: 'rSigner3', weight: 1 },
          ],
        },
      });

      const result = await orchestrator.addSignature(requestId, {
        signer: 'rSigner1',
        signature: 'VALID_SIGNATURE_HEX',
      });

      expect(result.success).toBe(true);
      expect(result.request.signatures).toHaveLength(1);
      expect(result.request.currentWeight).toBe(1);
    });

    it('should reject signature from unauthorized signer', async () => {
      const orchestrator = new MultiSignOrchestrator({
        storePath: '/test/multisig',
        signerList: {
          quorum: 2,
          signers: [
            { address: 'rSigner1', weight: 1 },
            { address: 'rSigner2', weight: 1 },
          ],
        },
      });

      await expect(
        orchestrator.addSignature(requestId, {
          signer: 'rUnauthorized',
          signature: 'SIGNATURE',
        })
      ).rejects.toThrow('Signer not in signer list');
    });

    it('should reject duplicate signature from same signer', async () => {
      const orchestrator = new MultiSignOrchestrator({
        storePath: '/test/multisig',
        signerList: {
          quorum: 2,
          signers: [
            { address: 'rSigner1', weight: 1 },
            { address: 'rSigner2', weight: 1 },
          ],
        },
      });

      await orchestrator.addSignature(requestId, {
        signer: 'rSigner1',
        signature: 'SIGNATURE_1',
      });

      await expect(
        orchestrator.addSignature(requestId, {
          signer: 'rSigner1',
          signature: 'SIGNATURE_2',
        })
      ).rejects.toThrow('Signer already signed');
    });

    it('should mark quorum met when threshold reached', async () => {
      const orchestrator = new MultiSignOrchestrator({
        storePath: '/test/multisig',
        signerList: {
          quorum: 2,
          signers: [
            { address: 'rSigner1', weight: 1 },
            { address: 'rSigner2', weight: 1 },
            { address: 'rSigner3', weight: 1 },
          ],
        },
      });

      await orchestrator.addSignature(requestId, {
        signer: 'rSigner1',
        signature: 'SIG1',
      });

      const result = await orchestrator.addSignature(requestId, {
        signer: 'rSigner2',
        signature: 'SIG2',
      });

      expect(result.request.quorumMet).toBe(true);
      expect(result.request.status).toBe('ready');
    });

    it('should handle weighted signers correctly', async () => {
      const orchestrator = new MultiSignOrchestrator({
        storePath: '/test/multisig',
        signerList: {
          quorum: 3,
          signers: [
            { address: 'rSigner1', weight: 2 },  // High weight
            { address: 'rSigner2', weight: 1 },
            { address: 'rSigner3', weight: 1 },
          ],
        },
      });

      const request = await orchestrator.createRequest({
        transaction: {
          TransactionType: 'Payment',
          Account: 'rMultiSigWallet',
          Destination: 'rDest123',
          Amount: '5000000000',
        },
        initiator: 'rSigner1',
      });

      // Single high-weight signer + one regular = quorum
      await orchestrator.addSignature(request.id, {
        signer: 'rSigner1',
        signature: 'SIG1',
      });

      const result = await orchestrator.addSignature(request.id, {
        signer: 'rSigner2',
        signature: 'SIG2',
      });

      expect(result.request.currentWeight).toBe(3);
      expect(result.request.quorumMet).toBe(true);
    });
  });

  describe('expiration', () => {
    it('should reject signature on expired request', async () => {
      const orchestrator = new MultiSignOrchestrator({
        storePath: '/test/multisig',
        signerList: {
          quorum: 2,
          signers: [
            { address: 'rSigner1', weight: 1 },
            { address: 'rSigner2', weight: 1 },
          ],
        },
        expirationMs: 3600000, // 1 hour
      });

      const request = await orchestrator.createRequest({
        transaction: {
          TransactionType: 'Payment',
          Account: 'rMultiSigWallet',
          Destination: 'rDest123',
          Amount: '5000000000',
        },
        initiator: 'rSigner1',
      });

      // Advance past expiration
      mockTime.advance(3600001);

      await expect(
        orchestrator.addSignature(request.id, {
          signer: 'rSigner1',
          signature: 'SIG',
        })
      ).rejects.toThrow('Request expired');
    });

    it('should update status to expired on check', async () => {
      const orchestrator = new MultiSignOrchestrator({
        storePath: '/test/multisig',
        signerList: {
          quorum: 2,
          signers: [
            { address: 'rSigner1', weight: 1 },
            { address: 'rSigner2', weight: 1 },
          ],
        },
        expirationMs: 3600000,
      });

      const request = await orchestrator.createRequest({
        transaction: {
          TransactionType: 'Payment',
          Account: 'rMultiSigWallet',
          Destination: 'rDest123',
          Amount: '5000000000',
        },
        initiator: 'rSigner1',
      });

      mockTime.advance(3600001);

      const status = await orchestrator.getRequest(request.id);
      expect(status.status).toBe('expired');
    });
  });

  describe('submission', () => {
    it('should combine signatures and submit when quorum met', async () => {
      const orchestrator = new MultiSignOrchestrator({
        storePath: '/test/multisig',
        xrplClient: mockXrpl.client,
        signerList: {
          quorum: 2,
          signers: [
            { address: 'rSigner1', weight: 1 },
            { address: 'rSigner2', weight: 1 },
          ],
        },
      });

      const request = await orchestrator.createRequest({
        transaction: {
          TransactionType: 'Payment',
          Account: 'rMultiSigWallet',
          Destination: 'rDest123',
          Amount: '5000000000',
        },
        initiator: 'rSigner1',
      });

      await orchestrator.addSignature(request.id, {
        signer: 'rSigner1',
        signature: 'SIG1',
      });

      await orchestrator.addSignature(request.id, {
        signer: 'rSigner2',
        signature: 'SIG2',
      });

      const result = await orchestrator.submit(request.id);

      expect(result.success).toBe(true);
      expect(mockXrpl.client.submit).toHaveBeenCalled();
    });

    it('should reject submission before quorum met', async () => {
      const orchestrator = new MultiSignOrchestrator({
        storePath: '/test/multisig',
        signerList: {
          quorum: 2,
          signers: [
            { address: 'rSigner1', weight: 1 },
            { address: 'rSigner2', weight: 1 },
          ],
        },
      });

      const request = await orchestrator.createRequest({
        transaction: {
          TransactionType: 'Payment',
          Account: 'rMultiSigWallet',
          Destination: 'rDest123',
          Amount: '5000000000',
        },
        initiator: 'rSigner1',
      });

      // Only one signature
      await orchestrator.addSignature(request.id, {
        signer: 'rSigner1',
        signature: 'SIG1',
      });

      await expect(orchestrator.submit(request.id)).rejects.toThrow(
        'Quorum not met'
      );
    });
  });
});
```

---

## 6. Assertion Patterns

### 6.1 Standard Assertions

```typescript
// Value assertions
expect(value).toBe(expected);           // Strict equality
expect(value).toEqual(expected);        // Deep equality
expect(value).toBeDefined();
expect(value).toBeUndefined();
expect(value).toBeNull();
expect(value).toBeTruthy();
expect(value).toBeFalsy();

// Number assertions
expect(number).toBeGreaterThan(3);
expect(number).toBeGreaterThanOrEqual(3);
expect(number).toBeLessThan(5);
expect(number).toBeCloseTo(0.3, 5);     // Floating point

// String assertions
expect(string).toMatch(/pattern/);
expect(string).toContain('substring');
expect(string).toHaveLength(10);

// Array assertions
expect(array).toContain(item);
expect(array).toContainEqual({ id: 1 });
expect(array).toHaveLength(5);

// Object assertions
expect(object).toHaveProperty('key');
expect(object).toHaveProperty('key', value);
expect(object).toMatchObject({ subset: true });

// Error assertions
expect(() => fn()).toThrow();
expect(() => fn()).toThrow(Error);
expect(() => fn()).toThrow('message');
expect(() => fn()).toThrow(/pattern/);

// Async assertions
await expect(promise).resolves.toBe(value);
await expect(promise).rejects.toThrow();
```

### 6.2 Custom Matchers

```typescript
// src/test/matchers.ts
import { expect } from 'vitest';

expect.extend({
  // XRPL-specific matchers
  toBeValidXRPLAddress(received: string) {
    const xrplAddressRegex = /^r[1-9A-HJ-NP-Za-km-z]{24,34}$/;
    const xAddressRegex = /^X[1-9A-HJ-NP-Za-km-z]{46}$/;
    const isValid = xrplAddressRegex.test(received) || xAddressRegex.test(received);

    return {
      pass: isValid,
      message: () =>
        isValid
          ? `expected ${received} not to be a valid XRPL address`
          : `expected ${received} to be a valid XRPL address`,
    };
  },

  toBeValidTransactionHash(received: string) {
    const hashRegex = /^[A-F0-9]{64}$/;
    const isValid = hashRegex.test(received);

    return {
      pass: isValid,
      message: () =>
        isValid
          ? `expected ${received} not to be a valid transaction hash`
          : `expected ${received} to be a valid 64-character hex transaction hash`,
    };
  },

  // Security-specific matchers
  toBeSecurelyCleared(received: Buffer) {
    const isCleared = received.every(byte => byte === 0);

    return {
      pass: isCleared,
      message: () =>
        isCleared
          ? `expected buffer not to be cleared`
          : `expected buffer to be securely cleared (all zeros)`,
    };
  },

  toHaveSecureFilePermissions(received: number) {
    const isSecure = (received & 0o077) === 0; // No group/other access

    return {
      pass: isSecure,
      message: () =>
        isSecure
          ? `expected permissions ${received.toString(8)} to allow group/other access`
          : `expected permissions ${received.toString(8)} to restrict group/other access`,
    };
  },

  // Async timing matchers
  async toCompleteWithin(received: Promise<unknown>, timeoutMs: number) {
    const start = Date.now();
    try {
      await received;
      const duration = Date.now() - start;
      const pass = duration <= timeoutMs;

      return {
        pass,
        message: () =>
          pass
            ? `expected operation to take longer than ${timeoutMs}ms`
            : `expected operation to complete within ${timeoutMs}ms but took ${duration}ms`,
      };
    } catch (error) {
      return {
        pass: false,
        message: () => `operation failed with error: ${error}`,
      };
    }
  },
});

// Type declarations
declare module 'vitest' {
  interface Assertion<T = any> {
    toBeValidXRPLAddress(): T;
    toBeValidTransactionHash(): T;
    toBeSecurelyCleared(): T;
    toHaveSecureFilePermissions(): T;
    toCompleteWithin(timeoutMs: number): Promise<T>;
  }
}
```

### 6.3 Snapshot Testing

```typescript
// For complex object structures
it('should generate correct wallet metadata', async () => {
  const keystore = new LocalFileKeystoreProvider({ keystorePath: testDir });
  const result = await keystore.createWallet('passphrase');

  // Remove non-deterministic fields
  const snapshot = {
    ...result,
    address: '[WALLET_ADDRESS]',
    createdAt: '[TIMESTAMP]',
  };

  expect(snapshot).toMatchSnapshot();
});

// For error messages
it('should produce helpful error message', () => {
  try {
    validateAddress('invalid');
    expect.fail('Should have thrown');
  } catch (error) {
    expect(error.message).toMatchSnapshot();
  }
});
```

---

## 7. Coverage Targets

### 7.1 Overall Targets

| Metric | Target | Minimum |
|--------|--------|---------|
| Line Coverage | 90% | 85% |
| Branch Coverage | 90% | 85% |
| Function Coverage | 90% | 85% |
| Statement Coverage | 90% | 85% |

### 7.2 Security-Critical Paths

| Component | Target | Minimum |
|-----------|--------|---------|
| `src/keystore/**` | 95% | 92% |
| `src/crypto/**` | 95% | 92% |
| `src/policy/**` | 95% | 92% |
| `src/validators/**` | 95% | 92% |
| `src/multisig/**` | 95% | 92% |

### 7.3 Uncovered Code Allowances

The following patterns are acceptable to exclude from coverage:

```typescript
// vitest.config.ts coverage.exclude
[
  // Type definitions
  '**/*.d.ts',
  '**/types/**',

  // Re-export files
  '**/index.ts',

  // Development utilities
  '**/dev/**',
  '**/scripts/**',

  // Generated code
  '**/generated/**',

  // Test files themselves
  '**/*.test.ts',
  '**/*.spec.ts',
  '**/test/**',
  '**/__mocks__/**',
]
```

### 7.4 Coverage Enforcement

```yaml
# .github/workflows/test.yml
- name: Run Tests with Coverage
  run: npm run test:coverage

- name: Check Coverage Thresholds
  run: |
    # Extract coverage percentages
    LINES=$(jq '.total.lines.pct' coverage/coverage-summary.json)
    BRANCHES=$(jq '.total.branches.pct' coverage/coverage-summary.json)

    # Fail if below minimum
    if (( $(echo "$LINES < 85" | bc -l) )); then
      echo "Line coverage $LINES% is below minimum 85%"
      exit 1
    fi

    if (( $(echo "$BRANCHES < 85" | bc -l) )); then
      echo "Branch coverage $BRANCHES% is below minimum 85%"
      exit 1
    fi
```

---

## 8. Example Test Files

### 8.1 Complete Keystore Test File

See Section 5.1 for the full `src/keystore/local-keystore.test.ts` example.

### 8.2 Complete Validator Test File

See Section 5.4 for the full `src/validators/schemas.test.ts` example.

### 8.3 Test Fixture Files

```typescript
// src/test/fixtures/wallets.ts
export const TEST_WALLETS = {
  valid: {
    address: 'rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh',
    publicKey: 'ED5F5AC8B98974A3CA843326D9B88CEBD36EFCFCD6F7D7A8C3C4F9E5C6A8B9D7E2',
    // Note: Never include real private keys in tests
    seed: 'sEdTM1uX8pu2do5XvTnutH6HsouMaM2',
  },

  testnet: {
    address: 'rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe',
    publicKey: 'ED1234567890ABCDEF...',
    seed: 'sTestnetSeed...',
  },

  multiSig: {
    account: 'rMultiSigAccount123',
    signers: [
      { address: 'rSigner1', weight: 1 },
      { address: 'rSigner2', weight: 1 },
      { address: 'rSigner3', weight: 2 },
    ],
    quorum: 3,
  },
};

export const INVALID_ADDRESSES = [
  '',
  'not-an-address',
  'rInvalidChecksum123456789012345',
  'r' + '1'.repeat(50), // Too long
  'r123', // Too short
  'sHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh', // Wrong prefix
];
```

```typescript
// src/test/fixtures/transactions.ts
export const TEST_TRANSACTIONS = {
  payment: {
    tier1: {
      TransactionType: 'Payment',
      Account: 'rSender123',
      Destination: 'rDest456',
      Amount: '50000000', // 50 XRP
    },
    tier2: {
      TransactionType: 'Payment',
      Account: 'rSender123',
      Destination: 'rDest456',
      Amount: '500000000', // 500 XRP
    },
    tier3: {
      TransactionType: 'Payment',
      Account: 'rSender123',
      Destination: 'rDest456',
      Amount: '5000000000', // 5000 XRP
    },
  },

  trustSet: {
    TransactionType: 'TrustSet',
    Account: 'rAccount123',
    LimitAmount: {
      currency: 'USD',
      issuer: 'rIssuer456',
      value: '1000000',
    },
  },

  accountSet: {
    TransactionType: 'AccountSet',
    Account: 'rAccount123',
    SetFlag: 8, // asfDefaultRipple
  },
};
```

```typescript
// src/test/fixtures/policies.ts
export const TEST_POLICIES = {
  default: {
    limits: {
      tier1: {
        maxPerTransaction: 100,
        maxPerDay: 500,
        maxPerMonth: 5000,
      },
      tier2: {
        maxPerTransaction: 1000,
        maxPerDay: 5000,
        requiresApproval: true,
      },
      tier3: {
        requiresMultiSig: true,
        minSignatures: 2,
      },
    },
  },

  strict: {
    limits: {
      tier1: {
        maxPerTransaction: 10,
        maxPerDay: 50,
      },
      tier2: {
        maxPerTransaction: 100,
        requiresApproval: true,
        require2FA: true,
      },
      tier3: {
        requiresMultiSig: true,
        minSignatures: 3,
        cooldownHours: 24,
      },
    },
  },

  permissive: {
    limits: {
      tier1: {
        maxPerTransaction: 1000,
        maxPerDay: 10000,
      },
      tier2: {
        maxPerTransaction: 10000,
      },
      tier3: {
        requiresMultiSig: false,
      },
    },
  },
};
```

---

## 9. Best Practices

### 9.1 Test Isolation

```typescript
// DO: Each test is independent
describe('WalletService', () => {
  let service: WalletService;

  beforeEach(() => {
    // Fresh instance for each test
    service = new WalletService();
  });

  it('test 1', () => { /* ... */ });
  it('test 2', () => { /* ... */ });
});

// DON'T: Tests sharing state
describe('WalletService', () => {
  const service = new WalletService(); // Shared!

  it('test 1', () => {
    service.createWallet(); // Affects test 2
  });

  it('test 2', () => {
    // May fail due to test 1's side effects
  });
});
```

### 9.2 Descriptive Test Names

```typescript
// DO: Clear, specific names
it('should throw InvalidPassphraseError when passphrase is less than 8 characters', () => {});
it('should encrypt private key with AES-256-GCM before saving to disk', () => {});
it('should reset daily limits at midnight UTC', () => {});

// DON'T: Vague names
it('should work', () => {});
it('handles errors', () => {});
it('test passphrase', () => {});
```

### 9.3 Testing Error Paths

```typescript
// DO: Test specific error types and messages
it('should throw AccountNotFoundError with address when account does not exist', async () => {
  await expect(client.getBalance('rNonExistent'))
    .rejects
    .toThrow(AccountNotFoundError);

  await expect(client.getBalance('rNonExistent'))
    .rejects
    .toMatchObject({
      code: 'ACCOUNT_NOT_FOUND',
      address: 'rNonExistent',
    });
});

// DON'T: Only check that some error is thrown
it('should throw error', async () => {
  await expect(client.getBalance('rNonExistent')).rejects.toThrow();
});
```

### 9.4 Avoiding Test Pollution

```typescript
// DO: Clean up after tests
afterEach(async () => {
  await cleanupTestFiles();
  vi.restoreAllMocks();
  vi.useRealTimers();
});

// DO: Use beforeEach for fresh state
beforeEach(() => {
  mockFs = createMockFileSystem();
  mockTime = createMockTime();
});
```

### 9.5 Testing Async Code

```typescript
// DO: Use async/await properly
it('should complete async operation', async () => {
  const result = await asyncOperation();
  expect(result).toBe(expected);
});

// DO: Test for rejections
it('should reject with error', async () => {
  await expect(asyncOperation()).rejects.toThrow('Error message');
});

// DON'T: Forget to await
it('broken test', () => {
  // This passes immediately without checking!
  expect(asyncOperation()).resolves.toBe(expected);
});
```

### 9.6 Mocking Best Practices

```typescript
// DO: Mock at the right level
vi.mock('fs/promises'); // Module-level mock

it('should read config', async () => {
  vi.mocked(readFile).mockResolvedValue('{"key": "value"}');
  // Test implementation
});

// DO: Use spies for verification
const spy = vi.spyOn(logger, 'info');
await operation();
expect(spy).toHaveBeenCalledWith('Expected message');

// DON'T: Over-mock implementation details
// If you're mocking private methods, consider testing via public API instead
```

### 9.7 Test Data Management

```typescript
// DO: Use fixtures for reusable test data
import { TEST_WALLETS, TEST_TRANSACTIONS } from '../fixtures';

it('should sign payment transaction', async () => {
  const result = await signer.sign(
    TEST_TRANSACTIONS.payment.tier1,
    TEST_WALLETS.valid
  );
  expect(result).toBeDefined();
});

// DO: Use factories for dynamic test data
function createTestTransaction(overrides = {}) {
  return {
    TransactionType: 'Payment',
    Account: 'rAccount123',
    Destination: 'rDest456',
    Amount: '1000000',
    ...overrides,
  };
}
```

---

## Appendix A: Test Command Reference

```bash
# Run all tests
npm test

# Run tests in watch mode
npm run test:watch

# Run specific test file
npm test src/keystore/local-keystore.test.ts

# Run tests matching pattern
npm test -- -t "should encrypt"

# Run with coverage
npm run test:coverage

# Run only security-critical tests
npm run test:security

# Run with verbose output
npm test -- --reporter=verbose

# Run in CI mode (with retries)
npm run test:ci

# Update snapshots
npm test -- -u

# Run specific describe block
npm test -- -t "LocalFileKeystoreProvider"
```

---

## Appendix B: Common Test Scenarios

### B.1 Testing Rate Limiting

```typescript
it('should block after max attempts', () => {
  const limiter = new RateLimiter({ maxAttempts: 3, windowMs: 60000 });

  expect(limiter.attempt()).toBe(true);
  expect(limiter.attempt()).toBe(true);
  expect(limiter.attempt()).toBe(true);
  expect(limiter.attempt()).toBe(false); // Blocked

  expect(limiter.getRemainingAttempts()).toBe(0);
  expect(limiter.getResetTime()).toBeGreaterThan(Date.now());
});
```

### B.2 Testing Retry Logic

```typescript
it('should retry on transient failure', async () => {
  const operation = vi.fn()
    .mockRejectedValueOnce(new Error('Temporary'))
    .mockRejectedValueOnce(new Error('Temporary'))
    .mockResolvedValue('Success');

  const result = await withRetry(operation, { maxRetries: 3 });

  expect(result).toBe('Success');
  expect(operation).toHaveBeenCalledTimes(3);
});
```

### B.3 Testing Event Emission

```typescript
it('should emit events on state change', async () => {
  const emitter = new StateEmitter();
  const listener = vi.fn();

  emitter.on('stateChange', listener);

  await emitter.setState('new-state');

  expect(listener).toHaveBeenCalledWith({
    previous: 'initial',
    current: 'new-state',
  });
});
```

---

## Document History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0.0 | 2026-01-28 | QA/DevOps Engineer | Initial specification |

---

## References

- [Vitest Documentation](https://vitest.dev/)
- [memfs Documentation](https://github.com/streamich/memfs)
- [XRPL.js Documentation](https://xrpl.org/docs)
- [Zod Documentation](https://zod.dev/)
- [local-keystore-spec.md](./local-keystore-spec.md)
- [xrpl-client-spec.md](./xrpl-client-spec.md)
- [multi-sign-spec.md](./multi-sign-spec.md)
- [policy-engine-spec.md](./policy-engine-spec.md)
- [audit-logger-spec.md](./audit-logger-spec.md)
