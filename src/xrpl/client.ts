/**
 * XRPL Client Wrapper
 *
 * Provides a robust wrapper around xrpl.js with connection management,
 * automatic retries, and transaction helpers.
 *
 * @module xrpl/client
 * @version 1.0.0
 * @since 2026-01-28
 */

import { Client, type TxResponse, type AccountInfoResponse, type SubmitResponse } from 'xrpl';
import type { Network, XRPLAddress, TransactionHash } from '../schemas/index.js';
import {
  getWebSocketUrl,
  getBackupWebSocketUrls,
  getConnectionConfig,
  type ConnectionConfig,
} from './config.js';

/**
 * XRPL Client configuration
 */
export interface XRPLClientConfig {
  /** Target network */
  network: Network;
  /** Custom WebSocket URL (overrides network default) */
  nodeUrl?: string;
  /** Connection configuration */
  connectionConfig?: Partial<ConnectionConfig>;
}

/**
 * Account information from XRPL
 */
export interface AccountInfo {
  /** Account address */
  account: string;
  /** Balance in drops */
  balance: string;
  /** Account sequence number */
  sequence: number;
  /** Number of objects owned (affects reserve) */
  ownerCount: number;
  /** Account flags */
  flags: number;
  /** Previous transaction ID */
  previousTxnID: string;
  /** Previous transaction ledger sequence */
  previousTxnLgrSeq: number;
}

/**
 * XRPL transaction submission result
 */
export interface XRPLTransactionResult {
  /** Transaction hash */
  hash: string;
  /** Result code (e.g., "tesSUCCESS") */
  resultCode: string;
  /** Ledger index where validated */
  ledgerIndex: number | undefined;
  /** Whether transaction was validated */
  validated: boolean;
  /** Transaction metadata */
  meta: unknown | undefined;
}

/**
 * Transaction history options
 */
export interface TxHistoryOptions {
  /** Maximum number of transactions to return */
  limit?: number;
  /** Oldest ledger index */
  ledgerIndexMin?: number;
  /** Newest ledger index */
  ledgerIndexMax?: number;
  /** Return transactions in chronological order */
  forward?: boolean;
}

/**
 * Submit options for transactions
 */
export interface SubmitOptions {
  /** Wait for validation (default: true) */
  waitForValidation?: boolean;
  /** Timeout for validation wait in ms (default: 20000) */
  timeout?: number;
  /** Fail if transaction not in validated ledger */
  failHard?: boolean;
}

/**
 * Wait options for transaction validation
 */
export interface WaitOptions {
  /** Timeout in milliseconds */
  timeout?: number;
  /** Poll interval in milliseconds */
  pollInterval?: number;
}

/**
 * Server information
 */
export interface ServerInfo {
  /** Server state (e.g., "full", "syncing") */
  server_state: string;
  /** Validated ledger information */
  validated_ledger:
    | {
        /** Ledger index */
        seq: number;
        /** Ledger hash */
        hash: string;
        /** Base reserve in XRP */
        reserve_base_xrp: number;
        /** Incremental reserve in XRP */
        reserve_inc_xrp: number;
        /** Base fee in XRP */
        base_fee_xrp: number;
      }
    | undefined;
  /** Complete ledgers range */
  complete_ledgers: string;
  /** Number of peers */
  peers: number | undefined;
  /** Validation quorum */
  validation_quorum: number | undefined;
}

/**
 * Custom error for XRPL client operations
 */
export class XRPLClientError extends Error {
  constructor(
    message: string,
    public code: string,
    public details?: unknown
  ) {
    super(message);
    this.name = 'XRPLClientError';
  }
}

/**
 * Connection failed error
 */
export class ConnectionError extends XRPLClientError {
  constructor(message: string, details?: unknown) {
    super(message, 'CONNECTION_ERROR', details);
    this.name = 'ConnectionError';
  }
}

/**
 * Account not found error
 */
export class AccountNotFoundError extends XRPLClientError {
  constructor(address: string) {
    super(`Account not found: ${address}`, 'ACCOUNT_NOT_FOUND', { address });
    this.name = 'AccountNotFoundError';
  }
}

/**
 * Transaction timeout error
 */
export class TransactionTimeoutError extends XRPLClientError {
  constructor(hash: string) {
    super(`Transaction not validated: ${hash}`, 'TX_TIMEOUT', { hash });
    this.name = 'TransactionTimeoutError';
  }
}

/**
 * Max reconnect attempts error
 */
export class MaxReconnectAttemptsError extends XRPLClientError {
  constructor(attempts: number) {
    super(`Maximum reconnection attempts reached: ${attempts}`, 'MAX_RECONNECT', { attempts });
    this.name = 'MaxReconnectAttemptsError';
  }
}

/**
 * Helper to sleep for specified milliseconds
 */
function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * XRPL Client Wrapper
 *
 * Provides connection management, auto-reconnection, and transaction helpers
 * for interacting with the XRPL.
 */
export class XRPLClientWrapper {
  private client: Client;
  private readonly network: Network;
  private readonly nodeUrl: string;
  private readonly backupUrls: string[];
  private readonly connectionConfig: ConnectionConfig;
  private currentUrlIndex: number = 0;
  private reconnectAttempts: number = 0;
  private isConnected: boolean = false;

  /**
   * Create a new XRPL client wrapper
   *
   * @param config - Client configuration
   */
  constructor(config: XRPLClientConfig) {
    this.network = config.network;
    this.nodeUrl = config.nodeUrl ?? getWebSocketUrl(config.network);
    this.backupUrls = getBackupWebSocketUrls(config.network);
    this.connectionConfig = {
      ...getConnectionConfig(),
      ...config.connectionConfig,
    };

    // Initialize xrpl.js client
    this.client = new Client(this.nodeUrl);
  }

  /**
   * Get the current network
   */
  public getNetwork(): Network {
    return this.network;
  }

  /**
   * Check if client is connected
   */
  public isClientConnected(): boolean {
    return this.isConnected && this.client.isConnected();
  }

  /**
   * Connect to XRPL network
   *
   * @throws {ConnectionError} If connection fails after all retries
   */
  public async connect(): Promise<void> {
    try {
      await this.client.connect();
      this.isConnected = true;
      this.reconnectAttempts = 0;
    } catch (error) {
      this.isConnected = false;
      throw new ConnectionError(`Failed to connect to ${this.nodeUrl}`, error);
    }
  }

  /**
   * Disconnect from XRPL network
   */
  public async disconnect(): Promise<void> {
    if (this.client.isConnected()) {
      await this.client.disconnect();
    }
    this.isConnected = false;
  }

  /**
   * Reconnect with exponential backoff
   *
   * @throws {MaxReconnectAttemptsError} If max attempts exceeded
   */
  private async reconnect(): Promise<void> {
    if (this.reconnectAttempts >= this.connectionConfig.maxReconnectAttempts) {
      throw new MaxReconnectAttemptsError(this.reconnectAttempts);
    }

    // Calculate backoff delay
    const delay = Math.min(
      this.connectionConfig.reconnectDelay *
        Math.pow(this.connectionConfig.reconnectBackoff, this.reconnectAttempts),
      30000 // Max 30 seconds
    );

    await sleep(delay);

    this.reconnectAttempts++;

    try {
      // Try backup URLs if available
      if (this.reconnectAttempts > 1 && this.backupUrls.length > 0) {
        this.currentUrlIndex = (this.currentUrlIndex + 1) % (this.backupUrls.length + 1);
        const url =
          this.currentUrlIndex === 0 ? this.nodeUrl : this.backupUrls[this.currentUrlIndex - 1]!;

        // Create new client with backup URL
        await this.client.disconnect();
        this.client = new Client(url);
      }

      await this.client.connect();
      this.isConnected = true;
      this.reconnectAttempts = 0;
    } catch (error) {
      // Recursive retry
      await this.reconnect();
    }
  }

  /**
   * Check server health
   *
   * @returns True if server is healthy (state is "full")
   */
  public async isHealthy(): Promise<boolean> {
    try {
      const response = await this.client.request({
        command: 'server_state',
      });
      return response.result.state.server_state === 'full';
    } catch {
      return false;
    }
  }

  /**
   * Get server information
   *
   * @returns Server information
   */
  public async getServerInfo(): Promise<ServerInfo> {
    const response = await this.client.request({
      command: 'server_info',
    });

    const info = response.result.info;
    return {
      server_state: info.server_state,
      validated_ledger: info.validated_ledger ?? undefined,
      complete_ledgers: info.complete_ledgers,
      peers: info.peers ?? undefined,
      validation_quorum: info.validation_quorum ?? undefined,
    };
  }

  /**
   * Get account information
   *
   * @param address - Account address
   * @returns Account information
   * @throws {AccountNotFoundError} If account doesn't exist
   */
  public async getAccountInfo(address: XRPLAddress): Promise<AccountInfo> {
    try {
      const response = (await this.client.request({
        command: 'account_info',
        account: address,
        ledger_index: 'validated',
      })) as AccountInfoResponse;

      const data = response.result.account_data;
      return {
        account: data.Account,
        balance: data.Balance,
        sequence: data.Sequence,
        ownerCount: data.OwnerCount,
        flags: data.Flags,
        previousTxnID: data.PreviousTxnID,
        previousTxnLgrSeq: data.PreviousTxnLgrSeq,
      };
    } catch (error: unknown) {
      if (typeof error === 'object' && error !== null && 'data' in error) {
        const errorData = error as { data?: { error?: string } };
        if (errorData.data?.error === 'actNotFound') {
          throw new AccountNotFoundError(address);
        }
      }
      throw error;
    }
  }

  /**
   * Get account balance in drops
   *
   * @param address - Account address
   * @returns Balance in drops
   */
  public async getBalance(address: XRPLAddress): Promise<string> {
    const accountInfo = await this.getAccountInfo(address);
    return accountInfo.balance;
  }

  /**
   * Get transaction information
   *
   * @param hash - Transaction hash
   * @returns Transaction response
   */
  public async getTransaction(hash: TransactionHash): Promise<TxResponse> {
    return this.client.request({
      command: 'tx',
      transaction: hash,
    }) as Promise<TxResponse>;
  }

  /**
   * Wait for transaction validation
   *
   * @param hash - Transaction hash
   * @param options - Wait options
   * @returns Transaction result
   * @throws {TransactionTimeoutError} If transaction not validated within timeout
   */
  public async waitForTransaction(
    hash: TransactionHash,
    options: WaitOptions = {}
  ): Promise<XRPLTransactionResult> {
    const timeout = options.timeout ?? 20000;
    const pollInterval = options.pollInterval ?? 1000;
    const startTime = Date.now();

    while (Date.now() - startTime < timeout) {
      try {
        const response = await this.client.request({
          command: 'tx',
          transaction: hash,
        });

        if (response.result.validated) {
          const meta = response.result.meta;
          const transactionResult =
            typeof meta === 'object' && meta !== null && 'XRPLTransactionResult' in meta
              ? (meta.XRPLTransactionResult as string)
              : 'unknown';

          return {
            hash,
            resultCode: transactionResult,
            ledgerIndex: response.result.ledger_index,
            validated: true,
            meta: response.result.meta,
          };
        }
      } catch (error: unknown) {
        // Transaction not found yet - keep waiting
        if (typeof error === 'object' && error !== null && 'data' in error) {
          const errorData = error as { data?: { error?: string } };
          if (errorData.data?.error !== 'txnNotFound') {
            throw error;
          }
        }
      }

      await sleep(pollInterval);
    }

    throw new TransactionTimeoutError(hash);
  }

  /**
   * Get current ledger index
   *
   * @returns Current validated ledger index
   */
  public async getCurrentLedgerIndex(): Promise<number> {
    const response = await this.client.request({
      command: 'ledger',
      ledger_index: 'validated',
    });
    return response.result.ledger_index;
  }

  /**
   * Get fee estimate for a transaction
   *
   * @returns Estimated fee in drops
   */
  public async getFee(): Promise<string> {
    const response = await this.client.request({
      command: 'fee',
    });
    return response.result.drops.open_ledger_fee;
  }

  /**
   * Get account transaction history
   *
   * @param address - Account address
   * @param options - History options
   * @returns Array of transactions
   */
  public async getAccountTransactions(
    address: XRPLAddress,
    options: TxHistoryOptions = {}
  ): Promise<unknown[]> {
    const response = await this.client.request({
      command: 'account_tx',
      account: address,
      ledger_index_min: options.ledgerIndexMin ?? -1,
      ledger_index_max: options.ledgerIndexMax ?? -1,
      limit: Math.min(options.limit ?? 50, 400),
      forward: options.forward ?? false,
    });

    return response.result.transactions.map((tx) => (tx as { tx: unknown }).tx);
  }

  /**
   * Submit a signed transaction
   *
   * @param signedTx - Signed transaction blob (hex string)
   * @param options - Submit options
   * @returns Transaction result
   */
  public async submitSignedTransaction(
    signedTx: string,
    options: SubmitOptions = {}
  ): Promise<XRPLTransactionResult> {
    const opts = {
      waitForValidation: true,
      timeout: 20000,
      failHard: false,
      ...options,
    };

    // Submit transaction
    const response = (await this.client.submit(signedTx, {
      failHard: opts.failHard,
    })) as SubmitResponse;

    const { tx_json, engine_result, engine_result_message } = response.result;
    const hash = tx_json.hash ?? 'unknown';

    // Check if submission succeeded
    if (engine_result !== 'tesSUCCESS' && !engine_result.startsWith('ter')) {
      throw new XRPLClientError(
        `Transaction submission failed: ${engine_result} - ${engine_result_message}`,
        'TX_SUBMIT_FAILED',
        { hash, engine_result, engine_result_message }
      );
    }

    // Wait for validation if requested
    if (opts.waitForValidation) {
      return this.waitForTransaction(hash as TransactionHash, { timeout: opts.timeout });
    }

    return {
      hash,
      resultCode: engine_result,
      ledgerIndex: undefined,
      validated: false,
      meta: undefined,
    };
  }
}
