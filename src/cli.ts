/**
 * XRPL Agent Wallet MCP Server - CLI Entry Point
 *
 * Initializes all services from environment variables and runs the MCP server.
 *
 * Environment Variables:
 * - XRPL_WALLET_PASSWORD (required): Master encryption password for keystore
 * - XRPL_NETWORK (optional): Target network - mainnet | testnet | devnet (default: testnet)
 * - XRPL_WALLET_KEYSTORE_PATH (optional): Keystore directory (default: ~/.xrpl-wallet-mcp)
 * - XRPL_WALLET_HMAC_KEY (optional): Hex-encoded 32-byte HMAC key for audit logs
 *
 * @module cli
 * @version 1.0.0
 */

import {
  // Keystore
  LocalKeystore,
  type KeystoreConfig,

  // Policy
  PolicyEngine,
  createTestPolicy,
  type InternalPolicy,

  // Signing
  SigningService,

  // Audit
  AuditLogger,
  generateHmacKey,
  createMemoryKeyProvider,

  // XRPL Client
  XRPLClientWrapper,

  // Server
  runServer,
  type ServerContext,

  // Utils
  type Network,
} from './index.js';

import { getRequiredEnv, getOptionalEnv, validateRequiredEnv } from './utils/env.js';

/**
 * Parse network from environment variable
 */
function parseNetwork(value: string): Network {
  const normalized = value.toLowerCase();
  if (normalized === 'mainnet' || normalized === 'testnet' || normalized === 'devnet') {
    return normalized;
  }
  throw new Error(`Invalid XRPL_NETWORK: ${value}. Must be mainnet, testnet, or devnet`);
}

/**
 * Get or generate HMAC key for audit logging
 */
function getHmacKey(): Buffer {
  const hexKey = process.env['XRPL_WALLET_HMAC_KEY'];
  if (hexKey) {
    const key = Buffer.from(hexKey, 'hex');
    if (key.length !== 32) {
      throw new Error('XRPL_WALLET_HMAC_KEY must be 32 bytes (64 hex characters)');
    }
    return key;
  }
  // Generate ephemeral key - logs will be valid for this session only
  console.error('[cli] No XRPL_WALLET_HMAC_KEY set, generating ephemeral HMAC key');
  return generateHmacKey();
}

/**
 * Main entry point
 */
async function main(): Promise<void> {
  console.error('[cli] Starting XRPL Agent Wallet MCP Server...');

  // 1. Validate required environment variables (fail fast)
  validateRequiredEnv([
    ['XRPL_WALLET_PASSWORD', 'Master encryption password for wallet keystore'],
  ]);

  // 2. Parse configuration from environment
  const network = parseNetwork(getOptionalEnv('XRPL_NETWORK', 'testnet'));
  const keystorePath = getOptionalEnv('XRPL_WALLET_KEYSTORE_PATH', '');
  const hmacKey = getHmacKey();

  console.error(`[cli] Network: ${network}`);
  console.error(`[cli] Keystore path: ${keystorePath || '~/.xrpl-wallet-mcp (default)'}`);

  // 3. Initialize LocalKeystore
  const keystore = new LocalKeystore();
  const keystoreConfig: KeystoreConfig = {
    ...(keystorePath ? { baseDir: keystorePath } : {}),
  };
  await keystore.initialize(keystoreConfig);
  console.error('[cli] Keystore initialized');

  // 4. Create PolicyEngine with test policy for the network
  // TODO: Support loading custom policy from XRPL_WALLET_POLICY file
  const policy: InternalPolicy = createTestPolicy(network);
  const policyEngine = new PolicyEngine(policy);
  console.error(`[cli] Policy engine initialized: ${policy.name}`);

  // 5. Create AuditLogger
  const auditLogger = await AuditLogger.create({
    hmacKeyProvider: createMemoryKeyProvider(hmacKey),
    config: {
      network,
      ...(keystorePath ? { baseDir: keystorePath } : {}),
    },
  });
  console.error('[cli] Audit logger initialized');

  // 6. Create XRPLClientWrapper
  const xrplClient = new XRPLClientWrapper({ network });
  console.error('[cli] XRPL client created');

  // 7. Create SigningService
  const signingService = new SigningService(keystore, auditLogger);
  console.error('[cli] Signing service initialized');

  // 8. Build server context
  const context: ServerContext = {
    keystore,
    policyEngine,
    signingService,
    auditLogger,
    xrplClient,
    network,
  };

  // 9. Run the MCP server
  console.error('[cli] Starting MCP server on stdio...');
  await runServer(context, {
    name: 'xrpl-agent-wallet-mcp',
    version: '0.1.2',
  });
}

// Run main and handle errors
main().catch((error: Error) => {
  console.error('[cli] Fatal error:', error.message);
  if (process.env['NODE_ENV'] !== 'production') {
    console.error(error.stack);
  }
  process.exit(1);
});
