/**
 * XRPL Network Configuration
 *
 * Provides network-specific configuration for XRPL connections including
 * WebSocket endpoints, explorers, and faucets.
 *
 * @module xrpl/config
 * @version 1.0.0
 * @since 2026-01-28
 */

import type { Network } from '../schemas/index.js';

/**
 * Network connection endpoints
 */
export interface NetworkEndpoints {
  /** WebSocket endpoints for this network */
  websocket: {
    /** Primary WebSocket URL */
    primary: string;
    /** Backup WebSocket URLs */
    backup: string[];
  };
  /** JSON-RPC endpoints (optional) */
  jsonRpc?: {
    /** Primary JSON-RPC URL */
    primary: string;
    /** Backup JSON-RPC URLs */
    backup: string[];
  };
}

/**
 * Explorer URL functions
 */
export interface ExplorerUrls {
  /** Main explorer URL */
  home: string;
  /** Account/wallet lookup */
  account: (address: string) => string;
  /** Transaction lookup */
  transaction: (hash: string) => string;
  /** Ledger lookup */
  ledger: (index: number) => string;
}

/**
 * Faucet configuration
 */
export interface FaucetConfig {
  /** Whether faucet is available for this network */
  available: boolean;
  /** Faucet API endpoint */
  url?: string;
  /** Amount dispensed per request (XRP) */
  amountXrp?: number;
  /** Rate limit window in seconds */
  rateLimitSeconds?: number;
  /** Rate limit requests per window */
  rateLimitRequests?: number;
}

/**
 * Connection configuration
 */
export interface ConnectionConfig {
  /** Connection timeout in milliseconds */
  connectionTimeout: number;
  /** Request timeout in milliseconds */
  requestTimeout: number;
  /** Maximum reconnection attempts */
  maxReconnectAttempts: number;
  /** Initial reconnection delay in milliseconds */
  reconnectDelay: number;
  /** Reconnection backoff multiplier */
  reconnectBackoff: number;
}

/**
 * Default network endpoints
 *
 * IMPORTANT: These are the official public endpoints. For production,
 * consider using a private node via environment variable override.
 */
export const NETWORK_ENDPOINTS: Record<Network, NetworkEndpoints> = {
  mainnet: {
    websocket: {
      primary: 'wss://xrplcluster.com',
      backup: ['wss://s1.ripple.com', 'wss://s2.ripple.com'],
    },
    jsonRpc: {
      primary: 'https://xrplcluster.com',
      backup: ['https://s1.ripple.com:51234', 'https://s2.ripple.com:51234'],
    },
  },
  testnet: {
    websocket: {
      primary: 'wss://s.altnet.rippletest.net:51233',
      backup: ['wss://testnet.xrpl-labs.com'],
    },
    jsonRpc: {
      primary: 'https://s.altnet.rippletest.net:51234',
      backup: [],
    },
  },
  devnet: {
    websocket: {
      primary: 'wss://s.devnet.rippletest.net:51233',
      backup: [],
    },
    jsonRpc: {
      primary: 'https://s.devnet.rippletest.net:51234',
      backup: [],
    },
  },
};

/**
 * Block explorer URLs
 */
export const EXPLORER_URLS: Record<Network, ExplorerUrls> = {
  mainnet: {
    home: 'https://xrpscan.com',
    account: (address) => `https://xrpscan.com/account/${address}`,
    transaction: (hash) => `https://xrpscan.com/tx/${hash}`,
    ledger: (index) => `https://xrpscan.com/ledger/${index}`,
  },
  testnet: {
    home: 'https://testnet.xrpl.org',
    account: (address) => `https://testnet.xrpl.org/accounts/${address}`,
    transaction: (hash) => `https://testnet.xrpl.org/transactions/${hash}`,
    ledger: (index) => `https://testnet.xrpl.org/ledgers/${index}`,
  },
  devnet: {
    home: 'https://devnet.xrpl.org',
    account: (address) => `https://devnet.xrpl.org/accounts/${address}`,
    transaction: (hash) => `https://devnet.xrpl.org/transactions/${hash}`,
    ledger: (index) => `https://devnet.xrpl.org/ledgers/${index}`,
  },
};

/**
 * Faucet configuration by network
 *
 * NOTE: As of 2026, testnet faucet provides ~100 XRP (previously 1000 XRP).
 * Do not hardcode faucet amounts in tests - use initial_balance_drops from wallet_fund response.
 */
export const FAUCET_CONFIG: Record<Network, FaucetConfig> = {
  mainnet: {
    available: false,
    // No faucet for mainnet - real XRP must be acquired through exchanges
  },
  testnet: {
    available: true,
    url: 'https://faucet.altnet.rippletest.net/accounts',
    amountXrp: 100, // Updated: was 1000, now ~100 XRP
    rateLimitSeconds: 60,
    rateLimitRequests: 1,
  },
  devnet: {
    available: true,
    url: 'https://faucet.devnet.rippletest.net/accounts',
    amountXrp: 100, // Updated: was 1000, now ~100 XRP
    rateLimitSeconds: 60,
    rateLimitRequests: 1,
  },
};

/**
 * Default connection configuration
 */
export const DEFAULT_CONNECTION_CONFIG: ConnectionConfig = {
  connectionTimeout: 10000, // 10 seconds
  requestTimeout: 30000, // 30 seconds
  maxReconnectAttempts: 3,
  reconnectDelay: 1000, // 1 second
  reconnectBackoff: 2, // Exponential backoff multiplier
};

/**
 * Get WebSocket URL for a network
 *
 * Checks for environment variable override first, then uses default.
 *
 * @param network - Target network
 * @returns WebSocket URL
 * @throws {Error} If custom URL doesn't use WSS protocol
 */
export function getWebSocketUrl(network: Network): string {
  // Check for environment override
  const envKey = `XRPL_${network.toUpperCase()}_WEBSOCKET_URL`;
  const customUrl = process.env[envKey];

  if (customUrl) {
    // Validate custom URL uses secure WebSocket
    if (!customUrl.startsWith('wss://') && !customUrl.startsWith('ws://localhost')) {
      throw new Error(
        `Custom endpoint must use WSS or ws://localhost: ${envKey}=${customUrl}`
      );
    }
    return customUrl;
  }

  return NETWORK_ENDPOINTS[network].websocket.primary;
}

/**
 * Get backup WebSocket URLs for a network
 *
 * @param network - Target network
 * @returns Array of backup WebSocket URLs
 */
export function getBackupWebSocketUrls(network: Network): string[] {
  return NETWORK_ENDPOINTS[network].websocket.backup;
}

/**
 * Get explorer URL for a transaction
 *
 * @param hash - Transaction hash
 * @param network - Network the transaction is on
 * @returns Explorer URL
 */
export function getTransactionExplorerUrl(hash: string, network: Network): string {
  return EXPLORER_URLS[network].transaction(hash);
}

/**
 * Get explorer URL for an account
 *
 * @param address - Account address
 * @param network - Network the account is on
 * @returns Explorer URL
 */
export function getAccountExplorerUrl(address: string, network: Network): string {
  return EXPLORER_URLS[network].account(address);
}

/**
 * Get explorer URL for a ledger
 *
 * @param index - Ledger index
 * @param network - Network the ledger is on
 * @returns Explorer URL
 */
export function getLedgerExplorerUrl(index: number, network: Network): string {
  return EXPLORER_URLS[network].ledger(index);
}

/**
 * Check if faucet is available for a network
 *
 * @param network - Network to check
 * @returns True if faucet is available
 */
export function isFaucetAvailable(network: Network): boolean {
  return FAUCET_CONFIG[network].available;
}

/**
 * Get faucet URL for a network
 *
 * @param network - Network to get faucet for
 * @returns Faucet URL or null if not available
 */
export function getFaucetUrl(network: Network): string | null {
  const config = FAUCET_CONFIG[network];
  return config.available ? config.url! : null;
}

/**
 * Get connection configuration with environment overrides
 *
 * @returns Connection configuration
 */
export function getConnectionConfig(): ConnectionConfig {
  const env = process.env as Record<string, string | undefined>;

  return {
    connectionTimeout: parseInt(
      env['XRPL_CONNECTION_TIMEOUT'] ?? String(DEFAULT_CONNECTION_CONFIG.connectionTimeout)
    ),
    requestTimeout: parseInt(
      env['XRPL_REQUEST_TIMEOUT'] ?? String(DEFAULT_CONNECTION_CONFIG.requestTimeout)
    ),
    maxReconnectAttempts: parseInt(
      env['XRPL_MAX_RECONNECT_ATTEMPTS'] ??
        String(DEFAULT_CONNECTION_CONFIG.maxReconnectAttempts)
    ),
    reconnectDelay: DEFAULT_CONNECTION_CONFIG.reconnectDelay,
    reconnectBackoff: DEFAULT_CONNECTION_CONFIG.reconnectBackoff,
  };
}
