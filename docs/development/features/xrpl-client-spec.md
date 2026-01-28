# XRPL Client Wrapper Specification

**Version**: 1.0.0
**Date**: 2026-01-28
**Status**: Draft

## 1. Overview

The `XRPLClient` class provides a robust, production-ready wrapper around xrpl.js with connection management, automatic retries, and transaction helpers. It integrates seamlessly with the local rippled node via MCP tools.

### 1.1 Design Goals

- **Reliability**: Automatic reconnection and health monitoring
- **Developer Experience**: Type-safe interfaces, clear error messages
- **Performance**: Connection pooling, efficient request handling
- **Security**: Client-side signing, validation, secure defaults
- **Testability**: Mock-friendly, deterministic behavior

### 1.2 Dependencies

```json
{
  "dependencies": {
    "xrpl": "^4.2.5",
    "winston": "^3.11.0"
  },
  "devDependencies": {
    "@types/node": "^20.0.0",
    "typescript": "^5.3.0"
  }
}
```

**CRITICAL**: Use xrpl.js 4.2.5+ only (4.2.1-4.2.4 compromised by CVE-2025-32965).

---

## 2. Class Interface

### 2.1 Core Class

```typescript
import { Client, Wallet, Transaction, TxResponse } from 'xrpl';

export interface XRPLClientConfig {
  /** WebSocket endpoint (default: ws://localhost:6006) */
  nodeUrl: string;

  /** Network type */
  network: 'mainnet' | 'testnet' | 'devnet' | 'local';

  /** Connection timeout in ms (default: 10000) */
  connectionTimeout?: number;

  /** Max reconnection attempts (default: 5) */
  maxReconnectAttempts?: number;

  /** Backoff multiplier for reconnects (default: 2) */
  reconnectBackoff?: number;

  /** Health check interval in ms (default: 30000) */
  healthCheckInterval?: number;

  /** Enable request/response logging */
  enableLogging?: boolean;

  /** Logger instance (default: console) */
  logger?: Logger;
}

export class XRPLClient {
  private client: Client;
  private config: Required<XRPLClientConfig>;
  private isConnected: boolean = false;
  private reconnectAttempts: number = 0;
  private healthCheckTimer?: NodeJS.Timer;

  constructor(config: XRPLClientConfig);

  // Lifecycle
  async connect(): Promise<void>;
  async disconnect(): Promise<void>;
  isHealthy(): Promise<boolean>;

  // Account Operations
  async getAccountInfo(address: string): Promise<AccountInfo>;
  async getAccountTransactions(
    address: string,
    options?: TxHistoryOptions
  ): Promise<Transaction[]>;
  async getAccountLines(address: string): Promise<TrustLine[]>;
  async getAccountOffers(address: string): Promise<Offer[]>;
  async getAccountNFTs(address: string): Promise<NFToken[]>;

  // Transaction Operations
  async submitTransaction(
    transaction: Transaction,
    wallet: Wallet,
    options?: SubmitOptions
  ): Promise<TxResult>;
  async getTransaction(txHash: string): Promise<TxResponse>;
  async waitForTransaction(
    txHash: string,
    options?: WaitOptions
  ): Promise<TxResult>;

  // DEX Operations
  async getOrderBook(
    takerGets: Currency,
    takerPays: Currency,
    limit?: number
  ): Promise<OrderBook>;
  async findPaymentPath(
    source: string,
    destination: string,
    amount: Amount,
    sendMax?: Amount
  ): Promise<PaymentPath[]>;

  // Ledger Operations
  async getCurrentLedgerIndex(): Promise<number>;
  async getLedgerInfo(ledgerIndex?: number): Promise<LedgerInfo>;
  async getServerInfo(): Promise<ServerInfo>;

  // Transaction Builders (helpers)
  preparePayment(params: PaymentParams): Payment;
  prepareOfferCreate(params: OfferParams): OfferCreate;
  prepareTrustSet(params: TrustSetParams): TrustSet;
  prepareNFTokenMint(params: NFTMintParams): NFTokenMint;

  // Fee & Sequence Management
  async estimateFee(transaction: Transaction): Promise<string>;
  async getNextSequence(address: string): Promise<number>;
  async autofill(transaction: Transaction): Promise<Transaction>;

  // Validation
  static isValidAddress(address: string): boolean;
  static isValidSeed(seed: string): boolean;
  static validateTransaction(transaction: Transaction): ValidationResult;
}
```

---

## 3. Connection Management

### 3.1 Connection Pooling

```typescript
class ConnectionPool {
  private connections: Map<string, Client> = new Map();
  private maxConnections: number = 5;

  async getConnection(nodeUrl: string): Promise<Client> {
    if (this.connections.has(nodeUrl)) {
      const client = this.connections.get(nodeUrl)!;
      if (client.isConnected()) return client;
    }

    const client = new Client(nodeUrl);
    await client.connect();
    this.connections.set(nodeUrl, client);
    return client;
  }

  async releaseConnection(nodeUrl: string): Promise<void> {
    const client = this.connections.get(nodeUrl);
    if (client) {
      await client.disconnect();
      this.connections.delete(nodeUrl);
    }
  }
}
```

### 3.2 Reconnection Strategy

**Exponential Backoff**:
```typescript
private async reconnect(): Promise<void> {
  if (this.reconnectAttempts >= this.config.maxReconnectAttempts) {
    throw new MaxReconnectAttemptsError();
  }

  const delay = Math.min(
    1000 * Math.pow(this.config.reconnectBackoff, this.reconnectAttempts),
    30000 // Max 30s delay
  );

  this.logger.info(`Reconnecting in ${delay}ms (attempt ${this.reconnectAttempts + 1})`);
  await sleep(delay);

  try {
    await this.client.connect();
    this.reconnectAttempts = 0;
    this.isConnected = true;
    this.startHealthCheck();
  } catch (error) {
    this.reconnectAttempts++;
    return this.reconnect();
  }
}
```

### 3.3 Health Checks

```typescript
private startHealthCheck(): void {
  this.healthCheckTimer = setInterval(async () => {
    try {
      await this.client.request({ command: 'ping' });
    } catch (error) {
      this.logger.error('Health check failed:', error);
      this.isConnected = false;
      await this.reconnect();
    }
  }, this.config.healthCheckInterval);
}

async isHealthy(): Promise<boolean> {
  try {
    const response = await this.client.request({
      command: 'server_state'
    });
    return response.result.state.server_state === 'full';
  } catch {
    return false;
  }
}
```

---

## 4. Key Operations

### 4.1 Account Information

```typescript
export interface AccountInfo {
  account: string;
  balance: string;
  sequence: number;
  ownerCount: number;
  flags: number;
  previousTxnID: string;
  previousTxnLgrSeq: number;
}

async getAccountInfo(address: string): Promise<AccountInfo> {
  if (!XRPLClient.isValidAddress(address)) {
    throw new InvalidAddressError(address);
  }

  try {
    const response = await this.client.request({
      command: 'account_info',
      account: address,
      ledger_index: 'validated'
    });

    return response.result.account_data;
  } catch (error) {
    if (error.data?.error === 'actNotFound') {
      throw new AccountNotFoundError(address);
    }
    throw error;
  }
}
```

### 4.2 Transaction History

```typescript
export interface TxHistoryOptions {
  limit?: number;          // Default: 50, Max: 400
  ledgerIndexMin?: number; // Oldest ledger
  ledgerIndexMax?: number; // Newest ledger
  binary?: boolean;        // Return binary format
  forward?: boolean;       // Chronological order
}

async getAccountTransactions(
  address: string,
  options: TxHistoryOptions = {}
): Promise<Transaction[]> {
  const response = await this.client.request({
    command: 'account_tx',
    account: address,
    ledger_index_min: options.ledgerIndexMin ?? -1,
    ledger_index_max: options.ledgerIndexMax ?? -1,
    limit: Math.min(options.limit ?? 50, 400),
    forward: options.forward ?? false,
  });

  return response.result.transactions.map(tx => tx.tx);
}
```

### 4.3 Submit Transaction

```typescript
export interface SubmitOptions {
  /** Wait for validation (default: true) */
  waitForValidation?: boolean;

  /** Timeout for validation wait in ms (default: 20000) */
  timeout?: number;

  /** Autofill transaction fields (default: true) */
  autofill?: boolean;

  /** Fail if tx not in validated ledger */
  failHard?: boolean;
}

export interface TxResult {
  hash: string;
  result: string;
  ledgerIndex: number;
  validated: boolean;
  meta?: TransactionMetadata;
}

async submitTransaction(
  transaction: Transaction,
  wallet: Wallet,
  options: SubmitOptions = {}
): Promise<TxResult> {
  const opts = {
    waitForValidation: true,
    timeout: 20000,
    autofill: true,
    ...options
  };

  // Autofill: Fee, Sequence, LastLedgerSequence
  let prepared = transaction;
  if (opts.autofill) {
    prepared = await this.autofill(transaction);
  }

  // Validate transaction structure
  const validation = XRPLClient.validateTransaction(prepared);
  if (!validation.valid) {
    throw new InvalidTransactionError(validation.errors);
  }

  // Sign transaction
  const signed = wallet.sign(prepared);

  // Submit
  const response = await this.client.submit(signed.tx_blob, {
    fail_hard: opts.failHard ?? false
  });

  if (response.result.engine_result !== 'tesSUCCESS' &&
      !response.result.engine_result.startsWith('ter')) {
    throw new TransactionFailedError(
      response.result.engine_result,
      response.result.engine_result_message
    );
  }

  // Wait for validation
  if (opts.waitForValidation) {
    return this.waitForTransaction(signed.hash, { timeout: opts.timeout });
  }

  return {
    hash: signed.hash,
    result: response.result.engine_result,
    ledgerIndex: 0,
    validated: false
  };
}
```

### 4.4 Wait for Validation

```typescript
export interface WaitOptions {
  timeout?: number; // Default: 20000ms
  pollInterval?: number; // Default: 1000ms
}

async waitForTransaction(
  txHash: string,
  options: WaitOptions = {}
): Promise<TxResult> {
  const timeout = options.timeout ?? 20000;
  const pollInterval = options.pollInterval ?? 1000;
  const startTime = Date.now();

  while (Date.now() - startTime < timeout) {
    try {
      const response = await this.client.request({
        command: 'tx',
        transaction: txHash
      });

      if (response.result.validated) {
        return {
          hash: txHash,
          result: response.result.meta.TransactionResult,
          ledgerIndex: response.result.ledger_index,
          validated: true,
          meta: response.result.meta
        };
      }
    } catch (error) {
      // Transaction not found yet
      if (error.data?.error !== 'txnNotFound') {
        throw error;
      }
    }

    await sleep(pollInterval);
  }

  throw new TransactionTimeoutError(txHash);
}
```

### 4.5 Get Current Ledger Index

```typescript
async getCurrentLedgerIndex(): Promise<number> {
  const response = await this.client.request({
    command: 'ledger',
    ledger_index: 'validated'
  });
  return response.result.ledger_index;
}
```

---

## 5. Transaction Building Helpers

### 5.1 Payment

```typescript
export interface PaymentParams {
  source: string;
  destination: string;
  amount: Amount;
  destinationTag?: number;
  sendMax?: Amount;
  paths?: Path[];
  memos?: Memo[];
}

preparePayment(params: PaymentParams): Payment {
  const payment: Payment = {
    TransactionType: 'Payment',
    Account: params.source,
    Destination: params.destination,
    Amount: typeof params.amount === 'string'
      ? params.amount
      : params.amount,
  };

  if (params.destinationTag !== undefined) {
    payment.DestinationTag = params.destinationTag;
  }

  if (params.sendMax) {
    payment.SendMax = params.sendMax;
  }

  if (params.paths) {
    payment.Paths = params.paths;
  }

  if (params.memos) {
    payment.Memos = params.memos;
  }

  return payment;
}
```

### 5.2 Offer Create

```typescript
export interface OfferParams {
  account: string;
  takerGets: Amount;
  takerPays: Amount;
  flags?: number; // tfPassive, tfImmediateOrCancel, tfFillOrKill, tfSell
  expiration?: number;
  offerSequence?: number; // To replace existing offer
}

prepareOfferCreate(params: OfferParams): OfferCreate {
  return {
    TransactionType: 'OfferCreate',
    Account: params.account,
    TakerGets: params.takerGets,
    TakerPays: params.takerPays,
    Flags: params.flags ?? 0,
    ...(params.expiration && { Expiration: params.expiration }),
    ...(params.offerSequence && { OfferSequence: params.offerSequence })
  };
}
```

### 5.3 Trust Set

```typescript
export interface TrustSetParams {
  account: string;
  limitAmount: IssuedCurrencyAmount;
  flags?: number; // tfSetNoRipple, tfClearNoRipple, tfSetFreeze, etc.
}

prepareTrustSet(params: TrustSetParams): TrustSet {
  return {
    TransactionType: 'TrustSet',
    Account: params.account,
    LimitAmount: params.limitAmount,
    Flags: params.flags ?? 0
  };
}
```

### 5.4 NFToken Mint

```typescript
export interface NFTMintParams {
  account: string;
  uri: string;
  taxon: number;
  transferFee?: number; // 0-50000 (0-50%)
  flags?: number; // tfBurnable, tfOnlyXRP, tfTransferable, tfMutable
}

prepareNFTokenMint(params: NFTMintParams): NFTokenMint {
  return {
    TransactionType: 'NFTokenMint',
    Account: params.account,
    URI: xrpl.convertStringToHex(params.uri),
    NFTokenTaxon: params.taxon,
    TransferFee: params.transferFee ?? 0,
    Flags: params.flags ?? 0
  };
}
```

---

## 6. Fee Estimation

### 6.1 Dynamic Fee Calculation

```typescript
async estimateFee(transaction: Transaction): Promise<string> {
  try {
    const response = await this.client.request({
      command: 'fee'
    });

    const drops = response.result.drops;

    // Use open_ledger_fee for current priority
    let baseFee = parseInt(drops.open_ledger_fee);

    // Special transaction costs
    if (transaction.TransactionType === 'AccountDelete') {
      baseFee = 2_000_000; // 2 XRP
    }

    // Multi-signature cost: (N+1) × base
    if (transaction.Signers && transaction.Signers.length > 0) {
      baseFee *= (transaction.Signers.length + 1);
    }

    // EscrowFinish with fulfillment: 10× base
    if (transaction.TransactionType === 'EscrowFinish' &&
        (transaction as EscrowFinish).Fulfillment) {
      baseFee *= 10;
    }

    return baseFee.toString();
  } catch (error) {
    // Fallback to minimum fee
    return '12'; // 12 drops (slightly above 10 drop minimum)
  }
}
```

### 6.2 Fee Levels

```typescript
export enum FeeLevel {
  MINIMUM = 'minimum',    // 10 drops
  LOW = 'low',            // open_ledger_fee
  MEDIUM = 'medium',      // median_fee
  HIGH = 'high'           // minimum_fee × 10
}

async getFeeForLevel(level: FeeLevel): Promise<string> {
  const response = await this.client.request({ command: 'fee' });
  const drops = response.result.drops;

  switch (level) {
    case FeeLevel.MINIMUM:
      return '10';
    case FeeLevel.LOW:
      return drops.open_ledger_fee;
    case FeeLevel.MEDIUM:
      return drops.median_fee;
    case FeeLevel.HIGH:
      return (parseInt(drops.minimum_fee) * 10).toString();
  }
}
```

---

## 7. Sequence Number Management

### 7.1 Get Next Sequence

```typescript
async getNextSequence(address: string): Promise<number> {
  const accountInfo = await this.getAccountInfo(address);
  return accountInfo.sequence;
}
```

### 7.2 Autofill Transaction

```typescript
async autofill(transaction: Transaction): Promise<Transaction> {
  // Get account info for sequence
  const accountInfo = await this.getAccountInfo(transaction.Account);

  // Get current ledger for LastLedgerSequence
  const currentLedger = await this.getCurrentLedgerIndex();

  // Estimate fee if not provided
  const fee = transaction.Fee ?? await this.estimateFee(transaction);

  return {
    ...transaction,
    Sequence: transaction.Sequence ?? accountInfo.sequence,
    Fee: fee,
    // CRITICAL: Prevent hanging transactions
    LastLedgerSequence: transaction.LastLedgerSequence ??
                       (currentLedger + 20)
  };
}
```

---

## 8. Error Handling and Retries

### 8.1 Custom Error Classes

```typescript
export class XRPLClientError extends Error {
  constructor(message: string, public code: string) {
    super(message);
    this.name = 'XRPLClientError';
  }
}

export class InvalidAddressError extends XRPLClientError {
  constructor(address: string) {
    super(`Invalid XRPL address: ${address}`, 'INVALID_ADDRESS');
  }
}

export class AccountNotFoundError extends XRPLClientError {
  constructor(address: string) {
    super(`Account not found: ${address}`, 'ACCOUNT_NOT_FOUND');
  }
}

export class TransactionFailedError extends XRPLClientError {
  constructor(
    public resultCode: string,
    public message: string
  ) {
    super(`Transaction failed: ${resultCode} - ${message}`, 'TX_FAILED');
  }
}

export class TransactionTimeoutError extends XRPLClientError {
  constructor(txHash: string) {
    super(`Transaction not validated: ${txHash}`, 'TX_TIMEOUT');
  }
}

export class MaxReconnectAttemptsError extends XRPLClientError {
  constructor() {
    super('Maximum reconnection attempts reached', 'MAX_RECONNECT');
  }
}
```

### 8.2 Retry Strategy

```typescript
async withRetry<T>(
  operation: () => Promise<T>,
  options: {
    maxAttempts?: number;
    retryDelay?: number;
    retryableErrors?: string[];
  } = {}
): Promise<T> {
  const maxAttempts = options.maxAttempts ?? 3;
  const retryDelay = options.retryDelay ?? 1000;
  const retryableErrors = options.retryableErrors ?? [
    'terQUEUED',
    'tefPAST_SEQ',
    'telINSUF_FEE_P'
  ];

  let lastError: Error;

  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    try {
      return await operation();
    } catch (error) {
      lastError = error;

      // Don't retry non-retryable errors
      if (error.data?.error &&
          !retryableErrors.includes(error.data.error)) {
        throw error;
      }

      if (attempt < maxAttempts) {
        this.logger.warn(`Attempt ${attempt} failed, retrying...`);
        await sleep(retryDelay * attempt);
      }
    }
  }

  throw lastError!;
}
```

### 8.3 Result Code Handling

```typescript
export function isRetryable(resultCode: string): boolean {
  return resultCode.startsWith('ter') || // Temporary error
         resultCode === 'tefPAST_SEQ' ||  // Refresh sequence
         resultCode === 'telINSUF_FEE_P'; // Increase fee
}

export function isPermanentFailure(resultCode: string): boolean {
  return resultCode.startsWith('tem') || // Malformed
         resultCode.startsWith('tef');   // Failed
}

export function isSuccess(resultCode: string): boolean {
  return resultCode === 'tesSUCCESS';
}

export function requiresFee(resultCode: string): boolean {
  return resultCode.startsWith('tec'); // Claimed but failed
}
```

---

## 9. Network-Specific Configuration

### 9.1 Network Presets

```typescript
export const NETWORK_PRESETS: Record<string, XRPLClientConfig> = {
  mainnet: {
    nodeUrl: 'wss://xrplcluster.com',
    network: 'mainnet',
    connectionTimeout: 10000,
    maxReconnectAttempts: 5,
    reconnectBackoff: 2,
    healthCheckInterval: 30000
  },

  testnet: {
    nodeUrl: 'wss://s.altnet.rippletest.net:51233',
    network: 'testnet',
    connectionTimeout: 10000,
    maxReconnectAttempts: 5,
    reconnectBackoff: 2,
    healthCheckInterval: 30000
  },

  devnet: {
    nodeUrl: 'wss://s.devnet.rippletest.net:51233',
    network: 'devnet',
    connectionTimeout: 10000,
    maxReconnectAttempts: 3,
    reconnectBackoff: 1.5,
    healthCheckInterval: 60000
  },

  local: {
    nodeUrl: 'ws://localhost:6006',
    network: 'local',
    connectionTimeout: 5000,
    maxReconnectAttempts: 3,
    reconnectBackoff: 1,
    healthCheckInterval: 15000
  }
};

// Usage
const client = new XRPLClient(NETWORK_PRESETS.mainnet);
```

### 9.2 Factory Method

```typescript
static createForNetwork(network: keyof typeof NETWORK_PRESETS): XRPLClient {
  const config = NETWORK_PRESETS[network];
  if (!config) {
    throw new Error(`Unknown network: ${network}`);
  }
  return new XRPLClient(config);
}

// Usage
const mainnetClient = XRPLClient.createForNetwork('mainnet');
const testnetClient = XRPLClient.createForNetwork('testnet');
```

---

## 10. Testnet Faucet Integration

### 10.1 Faucet Client

```typescript
export interface FaucetResult {
  account: string;
  balance: number;
  wallet: Wallet;
}

async fundTestnetAccount(wallet?: Wallet): Promise<FaucetResult> {
  if (this.config.network !== 'testnet') {
    throw new Error('Faucet only available on testnet');
  }

  try {
    const targetWallet = wallet ?? Wallet.generate('ed25519');

    const response = await fetch(
      'https://faucet.altnet.rippletest.net/accounts',
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ destination: targetWallet.address })
      }
    );

    if (!response.ok) {
      throw new Error(`Faucet request failed: ${response.statusText}`);
    }

    const data = await response.json();

    // Wait for account activation
    await this.waitForAccount(targetWallet.address);

    return {
      account: targetWallet.address,
      balance: data.balance,
      wallet: targetWallet
    };
  } catch (error) {
    throw new Error(`Failed to fund testnet account: ${error.message}`);
  }
}

private async waitForAccount(
  address: string,
  maxAttempts: number = 10
): Promise<void> {
  for (let i = 0; i < maxAttempts; i++) {
    try {
      await this.getAccountInfo(address);
      return; // Account exists
    } catch (error) {
      if (error instanceof AccountNotFoundError) {
        await sleep(1000);
        continue;
      }
      throw error;
    }
  }
  throw new Error('Account activation timeout');
}
```

---

## 11. Type Definitions

### 11.1 Core Types

```typescript
export type Amount = string | IssuedCurrencyAmount;

export interface IssuedCurrencyAmount {
  currency: string;
  issuer: string;
  value: string;
}

export interface Currency {
  currency: string;
  issuer?: string; // Required for non-XRP
}

export interface TrustLine {
  account: string;
  balance: string;
  currency: string;
  limit: string;
  limit_peer: string;
  no_ripple: boolean;
  no_ripple_peer: boolean;
}

export interface Offer {
  flags: number;
  seq: number;
  taker_gets: Amount;
  taker_pays: Amount;
  quality: string;
  expiration?: number;
}

export interface NFToken {
  NFTokenID: string;
  URI?: string;
  Flags: number;
  Issuer: string;
  NFTokenTaxon: number;
  TransferFee?: number;
}

export interface OrderBook {
  asks: BookOffer[];
  bids: BookOffer[];
}

export interface BookOffer {
  Account: string;
  BookDirectory: string;
  BookNode: string;
  Flags: number;
  LedgerEntryType: string;
  OwnerNode: string;
  PreviousTxnID: string;
  PreviousTxnLgrSeq: number;
  Sequence: number;
  TakerGets: Amount;
  TakerPays: Amount;
  index: string;
  owner_funds: string;
  quality: string;
}

export interface PaymentPath {
  paths: Path[][];
  source_amount: Amount;
  destination_amount?: Amount;
}

export interface Path {
  account?: string;
  currency?: string;
  issuer?: string;
  type?: number;
  type_hex?: string;
}

export interface Memo {
  Memo: {
    MemoType?: string;
    MemoData?: string;
    MemoFormat?: string;
  };
}

export interface ValidationResult {
  valid: boolean;
  errors: string[];
}

export interface ServerInfo {
  build_version: string;
  complete_ledgers: string;
  hostid: string;
  io_latency_ms: number;
  jq_trans_overflow: string;
  last_close: {
    converge_time_s: number;
    proposers: number;
  };
  load_factor: number;
  server_state: string;
  server_state_duration_us: string;
  state_accounting: Record<string, any>;
  time: string;
  uptime: number;
  validated_ledger: {
    age: number;
    base_fee_xrp: number;
    hash: string;
    reserve_base_xrp: number;
    reserve_inc_xrp: number;
    seq: number;
  };
  validation_quorum: number;
}

export interface LedgerInfo {
  ledger_index: number;
  ledger_hash: string;
  parent_hash: string;
  account_hash: string;
  transaction_hash: string;
  total_coins: string;
  close_time_human: string;
  close_time: number;
  close_time_resolution: number;
}
```

### 11.2 Transaction Types

```typescript
import {
  Payment,
  OfferCreate,
  OfferCancel,
  TrustSet,
  AccountSet,
  NFTokenMint,
  NFTokenBurn,
  NFTokenCreateOffer,
  NFTokenAcceptOffer,
  NFTokenCancelOffer,
  NFTokenModify,
  EscrowCreate,
  EscrowFinish,
  EscrowCancel,
  PaymentChannelCreate,
  PaymentChannelClaim,
  PaymentChannelFund,
  CheckCreate,
  CheckCash,
  CheckCancel,
  AccountDelete,
  AMMCreate,
  AMMDeposit,
  AMMWithdraw,
  AMMVote,
  AMMBid,
  AMMDelete,
  Clawback,
  DIDSet,
  DIDDelete
} from 'xrpl';

export type AnyTransaction =
  | Payment
  | OfferCreate
  | OfferCancel
  | TrustSet
  | AccountSet
  | NFTokenMint
  | NFTokenBurn
  | NFTokenCreateOffer
  | NFTokenAcceptOffer
  | NFTokenCancelOffer
  | NFTokenModify
  | EscrowCreate
  | EscrowFinish
  | EscrowCancel
  | PaymentChannelCreate
  | PaymentChannelClaim
  | PaymentChannelFund
  | CheckCreate
  | CheckCash
  | CheckCancel
  | AccountDelete
  | AMMCreate
  | AMMDeposit
  | AMMWithdraw
  | AMMVote
  | AMMBid
  | AMMDelete
  | Clawback
  | DIDSet
  | DIDDelete;
```

---

## 12. Validation

### 12.1 Address Validation

```typescript
static isValidAddress(address: string): boolean {
  try {
    return xrpl.isValidAddress(address);
  } catch {
    return false;
  }
}
```

### 12.2 Seed Validation

```typescript
static isValidSeed(seed: string): boolean {
  try {
    Wallet.fromSeed(seed);
    return true;
  } catch {
    return false;
  }
}
```

### 12.3 Transaction Validation

```typescript
static validateTransaction(transaction: Transaction): ValidationResult {
  const errors: string[] = [];

  // Required fields
  if (!transaction.TransactionType) {
    errors.push('TransactionType is required');
  }

  if (!transaction.Account) {
    errors.push('Account is required');
  } else if (!XRPLClient.isValidAddress(transaction.Account)) {
    errors.push('Invalid Account address');
  }

  // Fee validation
  if (transaction.Fee) {
    const fee = parseInt(transaction.Fee);
    if (isNaN(fee) || fee < 0) {
      errors.push('Invalid Fee amount');
    }
  }

  // Sequence validation
  if (transaction.Sequence !== undefined) {
    if (!Number.isInteger(transaction.Sequence) ||
        transaction.Sequence < 0) {
      errors.push('Invalid Sequence number');
    }
  }

  // LastLedgerSequence validation
  if (transaction.LastLedgerSequence !== undefined) {
    if (!Number.isInteger(transaction.LastLedgerSequence) ||
        transaction.LastLedgerSequence < 0) {
      errors.push('Invalid LastLedgerSequence');
    }
  }

  // Type-specific validation
  if (transaction.TransactionType === 'Payment') {
    const payment = transaction as Payment;

    if (!payment.Destination) {
      errors.push('Payment requires Destination');
    } else if (!XRPLClient.isValidAddress(payment.Destination)) {
      errors.push('Invalid Destination address');
    }

    if (!payment.Amount) {
      errors.push('Payment requires Amount');
    }
  }

  return {
    valid: errors.length === 0,
    errors
  };
}
```

---

## 13. Usage Examples

### 13.1 Initialize Client

```typescript
import { XRPLClient } from './xrpl-client';

// Local node
const client = new XRPLClient({
  nodeUrl: 'ws://localhost:6006',
  network: 'local',
  enableLogging: true
});

await client.connect();

// Or use preset
const mainnetClient = XRPLClient.createForNetwork('mainnet');
await mainnetClient.connect();
```

### 13.2 Check Account Balance

```typescript
const address = 'rN7n7otQDd6FczFgLdlqtyMVrn3HMbjVfb';

try {
  const accountInfo = await client.getAccountInfo(address);
  console.log(`Balance: ${xrpl.dropsToXrp(accountInfo.balance)} XRP`);
  console.log(`Sequence: ${accountInfo.sequence}`);
  console.log(`Owner Count: ${accountInfo.ownerCount}`);
} catch (error) {
  if (error instanceof AccountNotFoundError) {
    console.error('Account does not exist');
  } else {
    throw error;
  }
}
```

### 13.3 Send Payment

```typescript
import { Wallet, xrpl } from 'xrpl';

const wallet = Wallet.fromSeed(process.env.WALLET_SEED!);

const payment = client.preparePayment({
  source: wallet.address,
  destination: 'rRecipient...',
  amount: xrpl.xrpToDrops('10'),
  destinationTag: 12345
});

const result = await client.submitTransaction(payment, wallet);

if (isSuccess(result.result)) {
  console.log(`Payment successful: ${result.hash}`);
  console.log(`Validated in ledger: ${result.ledgerIndex}`);
} else {
  console.error(`Payment failed: ${result.result}`);
}
```

### 13.4 Place DEX Order

```typescript
const offer = client.prepareOfferCreate({
  account: wallet.address,
  takerGets: {
    currency: 'USD',
    issuer: 'rIssuer...',
    value: '100'
  },
  takerPays: xrpl.xrpToDrops('110')
});

const result = await client.submitTransaction(offer, wallet);
console.log(`Offer placed: ${result.hash}`);
```

### 13.5 Query Order Book

```typescript
const orderBook = await client.getOrderBook(
  { currency: 'USD', issuer: 'rvYAfWj5gh67oV6fW32ZzP3Aw4Eubs59B' },
  { currency: 'XRP' },
  50
);

console.log('Top Ask:', orderBook.asks[0]);
console.log('Top Bid:', orderBook.bids[0]);
```

---

## 14. Testing Strategy

### 14.1 Unit Tests

```typescript
import { jest } from '@jest/globals';
import { XRPLClient } from '../xrpl-client';

describe('XRPLClient', () => {
  let client: XRPLClient;

  beforeEach(() => {
    client = new XRPLClient({
      nodeUrl: 'ws://localhost:6006',
      network: 'local'
    });
  });

  afterEach(async () => {
    await client.disconnect();
  });

  describe('Address Validation', () => {
    it('should validate correct addresses', () => {
      expect(XRPLClient.isValidAddress('rN7n7otQDd6FczFgLdlqtyMVrn3HMbjVfb'))
        .toBe(true);
    });

    it('should reject invalid addresses', () => {
      expect(XRPLClient.isValidAddress('invalid')).toBe(false);
    });
  });

  describe('Connection', () => {
    it('should connect successfully', async () => {
      await client.connect();
      expect(await client.isHealthy()).toBe(true);
    });

    it('should reconnect on connection loss', async () => {
      // Test reconnection logic
    });
  });

  describe('Transaction Submission', () => {
    it('should autofill transaction fields', async () => {
      // Test autofill
    });

    it('should handle validation timeout', async () => {
      // Test timeout handling
    });
  });
});
```

### 14.2 Integration Tests

```typescript
describe('Integration Tests', () => {
  it('should submit and validate payment', async () => {
    const client = XRPLClient.createForNetwork('testnet');
    await client.connect();

    // Fund test account
    const faucet = await client.fundTestnetAccount();

    // Create recipient
    const recipient = Wallet.generate();
    await client.fundTestnetAccount(recipient);

    // Send payment
    const payment = client.preparePayment({
      source: faucet.wallet.address,
      destination: recipient.address,
      amount: xrpl.xrpToDrops('1')
    });

    const result = await client.submitTransaction(payment, faucet.wallet);

    expect(result.validated).toBe(true);
    expect(result.result).toBe('tesSUCCESS');

    await client.disconnect();
  });
});
```

---

## 15. Performance Considerations

### 15.1 Connection Pooling

- Reuse connections for multiple requests
- Maximum 5 concurrent connections per endpoint
- Automatic connection cleanup on idle

### 15.2 Request Batching

```typescript
async batchGetAccountInfo(addresses: string[]): Promise<AccountInfo[]> {
  return Promise.all(
    addresses.map(addr => this.getAccountInfo(addr))
  );
}
```

### 15.3 Caching

```typescript
private accountInfoCache = new Map<string, {
  data: AccountInfo;
  timestamp: number;
}>();

async getAccountInfo(
  address: string,
  useCache: boolean = true
): Promise<AccountInfo> {
  if (useCache) {
    const cached = this.accountInfoCache.get(address);
    if (cached && Date.now() - cached.timestamp < 5000) {
      return cached.data;
    }
  }

  const data = await this._fetchAccountInfo(address);
  this.accountInfoCache.set(address, { data, timestamp: Date.now() });
  return data;
}
```

---

## 16. Security Checklist

- [ ] Never log or expose private keys/seeds
- [ ] Validate all addresses before use
- [ ] Set LastLedgerSequence on all transactions
- [ ] Use autofill for fee/sequence management
- [ ] Verify transaction details before signing
- [ ] Sign transactions client-side only
- [ ] Use ed25519 algorithm (not secp256k1)
- [ ] Implement rate limiting
- [ ] Validate amount values (prevent overflow)
- [ ] Check reserve requirements before transactions
- [ ] Use HTTPS/WSS in production
- [ ] Sanitize user input
- [ ] Implement request timeouts
- [ ] Handle errors securely (no sensitive data in logs)

---

## 17. Next Steps

1. **Implementation**: Create `src/xrpl-client.ts` with full class
2. **Unit Tests**: Comprehensive test coverage
3. **Integration Tests**: Test against local rippled node
4. **Documentation**: JSDoc comments for all public methods
5. **Examples**: Create example scripts in `examples/`
6. **MCP Integration**: Connect with existing MCP tools

---

## References

- [xrpl.js Documentation](https://js.xrpl.org/)
- [XRPL Developer Portal](https://xrpl.org/)
- [Transaction Types](https://xrpl.org/transaction-types.html)
- [Result Codes](https://xrpl.org/transaction-results.html)
- [Local Node Setup](../infrastructure/local-node-setup.md)
- [MCP Integration](../mcp/integration-guide.md)

---

**Status**: Ready for Implementation
**Last Updated**: 2026-01-28
