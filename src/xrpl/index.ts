/**
 * XRPL Module Exports
 *
 * Provides unified access to XRPL client and configuration.
 *
 * @module xrpl
 * @version 1.0.0
 * @since 2026-01-28
 */

// Client exports
export {
  XRPLClientWrapper,
  type XRPLClientConfig,
  type AccountInfo,
  type XRPLTransactionResult,
  type TxHistoryOptions,
  type SubmitOptions,
  type WaitOptions,
  type ServerInfo,
  XRPLClientError,
  ConnectionError,
  AccountNotFoundError,
  TransactionTimeoutError,
  MaxReconnectAttemptsError,
} from './client.js';

// Configuration exports
export {
  type NetworkEndpoints,
  type ExplorerUrls,
  type FaucetConfig,
  type ConnectionConfig,
  NETWORK_ENDPOINTS,
  EXPLORER_URLS,
  FAUCET_CONFIG,
  DEFAULT_CONNECTION_CONFIG,
  getWebSocketUrl,
  getBackupWebSocketUrls,
  getTransactionExplorerUrl,
  getAccountExplorerUrl,
  getLedgerExplorerUrl,
  isFaucetAvailable,
  getFaucetUrl,
  getConnectionConfig,
} from './config.js';
