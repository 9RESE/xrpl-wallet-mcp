/**
 * MCP Server Implementation
 *
 * Main MCP server setup using @modelcontextprotocol/sdk.
 * Registers all wallet operation tools and wires up service dependencies.
 *
 * @module server
 * @version 1.0.0
 */

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  type CallToolRequest,
  type Tool,
} from '@modelcontextprotocol/sdk/types.js';

// Import all tool implementations
import { handleWalletCreate } from './tools/wallet-create.js';
import { handleWalletSign } from './tools/wallet-sign.js';
import { handleWalletBalance } from './tools/wallet-balance.js';
import { handleWalletPolicyCheck } from './tools/wallet-policy-check.js';
import { handleWalletRotate } from './tools/wallet-rotate.js';
import { handleWalletList } from './tools/wallet-list.js';
import { handleWalletHistory } from './tools/wallet-history.js';
import { handleWalletFund } from './tools/wallet-fund.js';
import { handlePolicySet } from './tools/policy-set.js';
import { handleTxSubmit } from './tools/tx-submit.js';
import { handleTxDecode } from './tools/tx-decode.js';

// Import service dependencies
import type { KeystoreProvider } from './keystore/interface.js';
import type { PolicyEngine } from './policy/engine.js';
import type { SigningService } from './signing/service.js';
import type { AuditLogger } from './audit/logger.js';
import type { XRPLClientWrapper } from './xrpl/client.js';

// Import zod for type inference
import { z } from 'zod';

// Import schemas for validation
import { InputSchemas, ErrorResponseSchema, type ErrorResponse } from './schemas/index.js';

// ============================================================================
// TYPES
// ============================================================================

/**
 * Server context holding all service instances.
 */
export interface ServerContext {
  keystore: KeystoreProvider;
  policyEngine: PolicyEngine;
  signingService: SigningService;
  auditLogger: AuditLogger;
  xrplClient: XRPLClientWrapper;
}

/**
 * Server configuration options.
 */
export interface ServerConfig {
  /** Server name (for MCP identification) */
  name?: string;
  /** Server version */
  version?: string;
}

// ============================================================================
// TOOL DEFINITIONS
// ============================================================================

/**
 * Tool metadata for MCP registration.
 * Defines all available tools with their schemas and descriptions.
 */
const TOOLS: Tool[] = [
  {
    name: 'wallet_create',
    description: 'Create a new XRPL wallet with policy controls. Generates keys locally with encrypted storage.',
    inputSchema: {
      type: 'object',
      properties: {
        network: { type: 'string', enum: ['mainnet', 'testnet', 'devnet'] },
        policy: { type: 'object' },
        wallet_name: { type: 'string' },
        funding_source: { type: 'string' },
        initial_funding_drops: { type: 'string' },
      },
      required: ['network', 'policy'],
    },
  },
  {
    name: 'wallet_sign',
    description: 'Sign a transaction with policy enforcement. Automatically fetches fresh sequence from ledger to prevent tefPAST_SEQ errors. Returns signed blob, pending approval, or rejection.',
    inputSchema: {
      type: 'object',
      properties: {
        wallet_address: { type: 'string' },
        unsigned_tx: { type: 'string' },
        context: { type: 'string' },
        auto_sequence: {
          type: 'boolean',
          default: true,
          description: 'Autofill sequence/fee/LastLedgerSequence from ledger before signing. Prevents tefPAST_SEQ in multi-tx workflows.',
        },
      },
      required: ['wallet_address', 'unsigned_tx'],
    },
  },
  {
    name: 'wallet_balance',
    description: 'Query wallet balance, reserves, and status. Returns current state from XRPL with ledger_index for verification.',
    inputSchema: {
      type: 'object',
      properties: {
        wallet_address: { type: 'string' },
        wait_after_tx: { type: 'number', minimum: 0, maximum: 30000, description: 'Wait time in ms before querying (for post-transaction timing)' },
      },
      required: ['wallet_address'],
    },
  },
  {
    name: 'wallet_policy_check',
    description: 'Dry-run policy evaluation without signing. Check if a transaction would be approved.',
    inputSchema: {
      type: 'object',
      properties: {
        wallet_address: { type: 'string' },
        unsigned_tx: { type: 'string' },
      },
      required: ['wallet_address', 'unsigned_tx'],
    },
  },
  {
    name: 'wallet_rotate',
    description: 'Rotate the agent wallet signing key. Disables old key and generates new one.',
    inputSchema: {
      type: 'object',
      properties: {
        wallet_address: { type: 'string' },
        reason: { type: 'string' },
      },
      required: ['wallet_address'],
    },
  },
  {
    name: 'wallet_list',
    description: 'List all managed wallets, optionally filtered by network.',
    inputSchema: {
      type: 'object',
      properties: {
        network: { type: 'string', enum: ['mainnet', 'testnet', 'devnet'] },
      },
    },
  },
  {
    name: 'wallet_history',
    description: 'Retrieve transaction history for audit and analysis.',
    inputSchema: {
      type: 'object',
      properties: {
        wallet_address: { type: 'string' },
        limit: { type: 'number', minimum: 1, maximum: 100 },
        marker: { type: 'string' },
      },
      required: ['wallet_address'],
    },
  },
  {
    name: 'wallet_fund',
    description: 'Fund wallet from testnet/devnet faucet with automatic retry until account is queryable. Returns initial_balance_drops for test verification.',
    inputSchema: {
      type: 'object',
      properties: {
        wallet_address: { type: 'string' },
        network: { type: 'string', enum: ['testnet', 'devnet'] },
        wait_for_confirmation: { type: 'boolean', description: 'Wait for account to be queryable on validated ledger (default: true)' },
      },
      required: ['wallet_address', 'network'],
    },
  },
  {
    name: 'policy_set',
    description: 'Update wallet policy (requires approval). Changes security constraints.',
    inputSchema: {
      type: 'object',
      properties: {
        wallet_address: { type: 'string' },
        policy: { type: 'object' },
        reason: { type: 'string' },
      },
      required: ['wallet_address', 'policy', 'reason'],
    },
  },
  {
    name: 'tx_submit',
    description: 'Submit signed transaction to XRPL network.',
    inputSchema: {
      type: 'object',
      properties: {
        signed_tx: { type: 'string' },
        network: { type: 'string', enum: ['mainnet', 'testnet', 'devnet'] },
        wait_for_validation: { type: 'boolean' },
      },
      required: ['signed_tx', 'network'],
    },
  },
  {
    name: 'tx_decode',
    description: 'Decode transaction blob for inspection. Works with signed or unsigned transactions.',
    inputSchema: {
      type: 'object',
      properties: {
        tx_blob: { type: 'string' },
      },
      required: ['tx_blob'],
    },
  },
];

// ============================================================================
// ERROR HANDLING
// ============================================================================

/**
 * Convert an error to MCP error response format.
 */
function formatError(error: unknown): ErrorResponse {
  const timestamp = new Date().toISOString();

  // If already an ErrorResponse, return it
  if (
    typeof error === 'object' &&
    error !== null &&
    'code' in error &&
    'message' in error &&
    'timestamp' in error
  ) {
    return error as ErrorResponse;
  }

  // Handle Error instances
  if (error instanceof Error) {
    // Only include stack traces in development mode (not in production)
    const isDevelopment = process.env['NODE_ENV'] !== 'production';

    // Log full error internally for debugging
    console.error('[Server] Internal error:', error.message);
    if (isDevelopment) {
      console.error(error.stack);
    }

    return {
      code: 'INTERNAL_ERROR',
      message: error.message,
      // Only include stack trace in development to avoid information disclosure
      details: isDevelopment ? { stack: error.stack } : undefined,
      timestamp,
    };
  }

  // Handle unknown error types
  return {
    code: 'INTERNAL_ERROR',
    message: 'An unknown error occurred',
    // Don't expose raw error details in production
    details: process.env['NODE_ENV'] !== 'production' ? { error: String(error) } : undefined,
    timestamp,
  };
}

// ============================================================================
// SERVER IMPLEMENTATION
// ============================================================================

/**
 * Create and initialize the MCP server.
 *
 * @param context - Service instances (keystore, policy, signing, audit, xrpl)
 * @param config - Server configuration options
 * @returns Configured MCP server instance
 */
export function createServer(context: ServerContext, config?: ServerConfig): Server {
  const server = new Server(
    {
      name: config?.name ?? 'xrpl-agent-wallet-mcp',
      version: config?.version ?? '0.1.0',
    },
    {
      capabilities: {
        tools: {},
      },
    }
  );

  // Register tools list handler
  server.setRequestHandler(ListToolsRequestSchema, async () => ({
    tools: TOOLS,
  }));

  // Register tool call handler
  server.setRequestHandler(CallToolRequestSchema, async (request: CallToolRequest) => {
    const { name, arguments: args } = request.params;

    try {
      // Validate tool exists
      const toolDef = TOOLS.find((t) => t.name === name);
      if (!toolDef) {
        throw new Error(`Unknown tool: ${name}`);
      }

      // Get input schema for validation
      const inputSchema = InputSchemas[name as keyof typeof InputSchemas];
      if (!inputSchema) {
        throw new Error(`No schema found for tool: ${name}`);
      }

      // Validate input against Zod schema
      const validatedInput = inputSchema.parse(args);

      // Route to appropriate handler with proper type assertions
      let result: unknown;
      switch (name) {
        case 'wallet_create':
          result = await handleWalletCreate(context, validatedInput as z.infer<typeof InputSchemas.wallet_create>);
          break;
        case 'wallet_sign':
          result = await handleWalletSign(context, validatedInput as z.infer<typeof InputSchemas.wallet_sign>);
          break;
        case 'wallet_balance':
          result = await handleWalletBalance(context, validatedInput as z.infer<typeof InputSchemas.wallet_balance>);
          break;
        case 'wallet_policy_check':
          result = await handleWalletPolicyCheck(context, validatedInput as z.infer<typeof InputSchemas.wallet_policy_check>);
          break;
        case 'wallet_rotate':
          result = await handleWalletRotate(context, validatedInput as z.infer<typeof InputSchemas.wallet_rotate>);
          break;
        case 'wallet_list':
          result = await handleWalletList(context, validatedInput as z.infer<typeof InputSchemas.wallet_list>);
          break;
        case 'wallet_history':
          result = await handleWalletHistory(context, validatedInput as z.infer<typeof InputSchemas.wallet_history>);
          break;
        case 'wallet_fund':
          result = await handleWalletFund(context, validatedInput as z.infer<typeof InputSchemas.wallet_fund>);
          break;
        case 'policy_set':
          result = await handlePolicySet(context, validatedInput as z.infer<typeof InputSchemas.policy_set>);
          break;
        case 'tx_submit':
          result = await handleTxSubmit(context, validatedInput as z.infer<typeof InputSchemas.tx_submit>);
          break;
        case 'tx_decode':
          result = await handleTxDecode(context, validatedInput as z.infer<typeof InputSchemas.tx_decode>);
          break;
        default:
          throw new Error(`Handler not implemented for tool: ${name}`);
      }

      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify(result, null, 2),
          },
        ],
      };
    } catch (error) {
      const errorResponse = formatError(error);

      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify(errorResponse, null, 2),
          },
        ],
        isError: true,
      };
    }
  });

  return server;
}

/**
 * Run the MCP server with stdio transport.
 *
 * @param context - Service instances
 * @param config - Server configuration
 */
export async function runServer(context: ServerContext, config?: ServerConfig): Promise<void> {
  const server = createServer(context, config);
  const transport = new StdioServerTransport();

  await server.connect(transport);

  // Log server start to audit
  await context.auditLogger.log({
    event: 'server_started',
  });

  console.error('XRPL Agent Wallet MCP Server running on stdio');
}
