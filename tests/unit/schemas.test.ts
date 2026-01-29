/**
 * Comprehensive tests for XRPL Agent Wallet MCP Schemas
 *
 * Tests cover:
 * - XRPL Primitives (addresses, amounts, hashes)
 * - Policy schemas
 * - MCP tool inputs and outputs
 * - Error handling
 * - Edge cases and boundary conditions
 */

import { describe, it, expect, expectTypeOf } from 'vitest';
import {
  // XRPL Primitives
  XRPLAddressSchema,
  DropsAmountSchema,
  DropsAmountOptionalZeroSchema,
  TransactionHashSchema,
  PublicKeySchema,
  NetworkSchema,
  TransactionTypeSchema,
  SequenceNumberSchema,
  LedgerIndexSchema,
  HexStringSchema,
  UnsignedTransactionBlobSchema,
  SignedTransactionBlobSchema,
  WalletIdSchema,
  WalletNameSchema,
  TimestampSchema,
  PaginationMarkerSchema,

  // Policy Schemas
  ApprovalTierSchema,
  PolicyLimitsSchema,
  DestinationModeSchema,
  PolicyDestinationsSchema,
  PolicyTransactionTypesSchema,
  PolicyTimeControlsSchema,
  PolicyEscalationSchema,
  PolicyNotificationsSchema,
  AgentWalletPolicySchema,

  // MCP Tool Input Schemas
  WalletCreateInputSchema,
  WalletSignInputSchema,
  WalletBalanceInputSchema,
  WalletPolicyCheckInputSchema,
  WalletRotateInputSchema,
  WalletHistoryInputSchema,
  WalletListInputSchema,
  WalletFundInputSchema,
  PolicySetInputSchema,
  TxSubmitInputSchema,
  TxDecodeInputSchema,
  NetworkConfigInputSchema,

  // MCP Tool Output Schemas
  WalletCreateOutputSchema,
  WalletSignOutputSchema,
  WalletSignApprovedOutputSchema,
  WalletSignPendingOutputSchema,
  WalletSignRejectedOutputSchema,
  WalletBalanceOutputSchema,
  WalletPolicyCheckOutputSchema,
  WalletRotateOutputSchema,
  WalletHistoryOutputSchema,
  WalletListOutputSchema,
  WalletFundOutputSchema,
  PolicySetOutputSchema,
  TxSubmitOutputSchema,
  TxDecodeOutputSchema,
  NetworkConfigOutputSchema,

  // Error Schemas
  ErrorCodeSchema,
  ErrorResponseSchema,

  // Audit Schemas
  AuditEventTypeSchema,
  AuditLogEntrySchema,

  // Types
  type XRPLAddress,
  type DropsAmount,
  type TransactionHash,
  type Network,
  type AgentWalletPolicy,
  type WalletSignOutput,
} from '../../src/schemas/index.js';

// ============================================================================
// XRPL PRIMITIVES TESTS
// ============================================================================

describe('XRPL Primitives', () => {
  describe('XRPLAddressSchema', () => {
    it('should accept valid XRPL addresses', () => {
      const validAddresses = [
        'rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh',
        'rN7n3473SaZBCG4dFL83w7a1RXtXtbk2D9',
        'rf1BiGeXwwQoi8Z2ueFYTEXSwuJYfV2Jpn',
        'rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe',
        'r3ADD8kXSUKHd6zTCKfnKT3zV9EZHjzp1S',
      ];

      for (const address of validAddresses) {
        const result = XRPLAddressSchema.safeParse(address);
        expect(result.success).toBe(true);
        if (result.success) {
          expect(result.data).toBe(address);
        }
      }
    });

    it('should reject invalid XRPL addresses', () => {
      const invalidAddresses = [
        '', // empty
        'r', // too short
        'rABC', // too short
        'xHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh', // wrong prefix
        'rHb9CJAWyB4rj91VRWn96DkukG4bwdtyT0', // contains 0
        'rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTO', // contains O
        'rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTI', // contains I
        'rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTl', // contains l
        'rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh@', // special char
        'rHb9CJAWyB4rj91VRWn96DkukG4bwdtyThXXXXXXXXXXXXX', // too long
      ];

      for (const address of invalidAddresses) {
        const result = XRPLAddressSchema.safeParse(address);
        expect(result.success).toBe(false);
      }
    });
  });

  describe('DropsAmountSchema', () => {
    it('should accept valid drops amounts', () => {
      const validAmounts = [
        '1', // minimum
        '1000000', // 1 XRP
        '1000000000000', // 1 million XRP
        '100000000000000000', // max (100 billion XRP)
      ];

      for (const amount of validAmounts) {
        const result = DropsAmountSchema.safeParse(amount);
        expect(result.success).toBe(true);
      }
    });

    it('should reject invalid drops amounts', () => {
      const invalidAmounts = [
        '0', // zero not allowed
        '-1', // negative
        '01', // leading zero
        '1.5', // decimal
        'abc', // non-numeric
        '', // empty
        '100000000000000001', // exceeds max
        '999999999999999999999', // way too large
      ];

      for (const amount of invalidAmounts) {
        const result = DropsAmountSchema.safeParse(amount);
        expect(result.success).toBe(false);
      }
    });
  });

  describe('DropsAmountOptionalZeroSchema', () => {
    it('should accept zero', () => {
      const result = DropsAmountOptionalZeroSchema.safeParse('0');
      expect(result.success).toBe(true);
    });

    it('should accept valid positive amounts', () => {
      const result = DropsAmountOptionalZeroSchema.safeParse('1000000');
      expect(result.success).toBe(true);
    });
  });

  describe('TransactionHashSchema', () => {
    it('should accept valid transaction hashes', () => {
      const validHashes = [
        'E08D6E9754025BA2534A78707605E0601F03ACE063687A0CA1BDDACFCD1698C7',
        'abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890',
        'ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890',
      ];

      for (const hash of validHashes) {
        const result = TransactionHashSchema.safeParse(hash);
        expect(result.success).toBe(true);
        if (result.success) {
          // Should be uppercased
          expect(result.data).toBe(hash.toUpperCase());
        }
      }
    });

    it('should reject invalid transaction hashes', () => {
      const invalidHashes = [
        '', // empty
        'E08D6E9754025BA2534A78707605E0601F03ACE063687A0CA1BDDACFCD1698C', // 63 chars
        'E08D6E9754025BA2534A78707605E0601F03ACE063687A0CA1BDDACFCD1698C7X', // 65 chars
        'G08D6E9754025BA2534A78707605E0601F03ACE063687A0CA1BDDACFCD1698C7', // invalid char G
        'E08D6E9754025BA2534A78707605E0601F03ACE063687A0CA1BDDACFCD1698C!', // special char
      ];

      for (const hash of invalidHashes) {
        const result = TransactionHashSchema.safeParse(hash);
        expect(result.success).toBe(false);
      }
    });
  });

  describe('PublicKeySchema', () => {
    it('should accept valid Ed25519 public keys', () => {
      const edKey = 'ED' + 'A'.repeat(64);
      const result = PublicKeySchema.safeParse(edKey);
      expect(result.success).toBe(true);
    });

    it('should accept valid secp256k1 public keys', () => {
      const key02 = '02' + 'A'.repeat(64);
      const key03 = '03' + 'B'.repeat(64);

      expect(PublicKeySchema.safeParse(key02).success).toBe(true);
      expect(PublicKeySchema.safeParse(key03).success).toBe(true);
    });

    it('should reject invalid public keys', () => {
      const invalidKeys = [
        '', // empty
        'ED' + 'A'.repeat(63), // too short
        'ED' + 'A'.repeat(65), // too long
        '04' + 'A'.repeat(64), // wrong prefix
        'XY' + 'A'.repeat(64), // invalid prefix
      ];

      for (const key of invalidKeys) {
        const result = PublicKeySchema.safeParse(key);
        expect(result.success).toBe(false);
      }
    });
  });

  describe('NetworkSchema', () => {
    it('should accept valid networks', () => {
      expect(NetworkSchema.safeParse('mainnet').success).toBe(true);
      expect(NetworkSchema.safeParse('testnet').success).toBe(true);
      expect(NetworkSchema.safeParse('devnet').success).toBe(true);
    });

    it('should reject invalid networks', () => {
      expect(NetworkSchema.safeParse('').success).toBe(false);
      expect(NetworkSchema.safeParse('localnet').success).toBe(false);
      expect(NetworkSchema.safeParse('MAINNET').success).toBe(false);
    });
  });

  describe('TransactionTypeSchema', () => {
    it('should accept valid transaction types', () => {
      const validTypes = ['Payment', 'EscrowCreate', 'EscrowFinish', 'TrustSet', 'AccountSet'];

      for (const type of validTypes) {
        expect(TransactionTypeSchema.safeParse(type).success).toBe(true);
      }
    });

    it('should reject invalid transaction types', () => {
      expect(TransactionTypeSchema.safeParse('InvalidType').success).toBe(false);
      expect(TransactionTypeSchema.safeParse('payment').success).toBe(false);
    });
  });

  describe('SequenceNumberSchema', () => {
    it('should accept valid sequence numbers', () => {
      expect(SequenceNumberSchema.safeParse(1).success).toBe(true);
      expect(SequenceNumberSchema.safeParse(1000000).success).toBe(true);
      expect(SequenceNumberSchema.safeParse(4294967295).success).toBe(true);
    });

    it('should reject invalid sequence numbers', () => {
      expect(SequenceNumberSchema.safeParse(0).success).toBe(false);
      expect(SequenceNumberSchema.safeParse(-1).success).toBe(false);
      expect(SequenceNumberSchema.safeParse(4294967296).success).toBe(false);
      expect(SequenceNumberSchema.safeParse(1.5).success).toBe(false);
    });
  });

  describe('LedgerIndexSchema', () => {
    it('should accept numeric ledger indices', () => {
      expect(LedgerIndexSchema.safeParse(1).success).toBe(true);
      expect(LedgerIndexSchema.safeParse(12345678).success).toBe(true);
    });

    it('should accept string ledger indices', () => {
      expect(LedgerIndexSchema.safeParse('validated').success).toBe(true);
      expect(LedgerIndexSchema.safeParse('closed').success).toBe(true);
      expect(LedgerIndexSchema.safeParse('current').success).toBe(true);
    });

    it('should reject invalid ledger indices', () => {
      expect(LedgerIndexSchema.safeParse(0).success).toBe(false);
      expect(LedgerIndexSchema.safeParse(-1).success).toBe(false);
      expect(LedgerIndexSchema.safeParse('invalid').success).toBe(false);
    });
  });

  describe('WalletIdSchema', () => {
    it('should accept valid wallet IDs', () => {
      const validIds = ['wallet-001', 'agent_wallet', 'MyWallet123', 'a'];

      for (const id of validIds) {
        expect(WalletIdSchema.safeParse(id).success).toBe(true);
      }
    });

    it('should reject invalid wallet IDs', () => {
      const invalidIds = [
        '', // empty
        '-wallet', // starts with hyphen
        '_wallet', // starts with underscore
        'wallet@123', // special character
        'a'.repeat(65), // too long
      ];

      for (const id of invalidIds) {
        expect(WalletIdSchema.safeParse(id).success).toBe(false);
      }
    });
  });

  describe('TimestampSchema', () => {
    it('should accept valid ISO 8601 timestamps', () => {
      // Zod's datetime() is strict about format - only accepts 'Z' suffix by default
      const validTimestamps = [
        '2026-01-28T14:30:00Z',
        '2026-01-28T14:30:00.123Z',
      ];

      for (const ts of validTimestamps) {
        expect(TimestampSchema.safeParse(ts).success).toBe(true);
      }
    });

    it('should reject invalid timestamps', () => {
      expect(TimestampSchema.safeParse('2026-01-28').success).toBe(false);
      expect(TimestampSchema.safeParse('invalid').success).toBe(false);
      expect(TimestampSchema.safeParse('').success).toBe(false);
    });
  });
});

// ============================================================================
// POLICY SCHEMA TESTS
// ============================================================================

describe('Policy Schemas', () => {
  describe('ApprovalTierSchema', () => {
    it('should accept valid tiers', () => {
      expect(ApprovalTierSchema.safeParse(1).success).toBe(true);
      expect(ApprovalTierSchema.safeParse(2).success).toBe(true);
      expect(ApprovalTierSchema.safeParse(3).success).toBe(true);
      expect(ApprovalTierSchema.safeParse(4).success).toBe(true);
    });

    it('should reject invalid tiers', () => {
      expect(ApprovalTierSchema.safeParse(0).success).toBe(false);
      expect(ApprovalTierSchema.safeParse(5).success).toBe(false);
      expect(ApprovalTierSchema.safeParse('1').success).toBe(false);
    });
  });

  describe('PolicyLimitsSchema', () => {
    it('should accept valid limits configuration', () => {
      const validLimits = {
        max_amount_per_tx_drops: '10000000',
        max_daily_volume_drops: '100000000',
        max_tx_per_hour: 10,
        max_tx_per_day: 50,
      };

      const result = PolicyLimitsSchema.safeParse(validLimits);
      expect(result.success).toBe(true);
    });

    it('should reject invalid limits', () => {
      // Missing required fields
      expect(PolicyLimitsSchema.safeParse({}).success).toBe(false);

      // Invalid values
      expect(
        PolicyLimitsSchema.safeParse({
          max_amount_per_tx_drops: '0', // zero not allowed
          max_daily_volume_drops: '100000000',
          max_tx_per_hour: 10,
          max_tx_per_day: 50,
        }).success
      ).toBe(false);

      // Invalid types
      expect(
        PolicyLimitsSchema.safeParse({
          max_amount_per_tx_drops: 10000000, // should be string
          max_daily_volume_drops: '100000000',
          max_tx_per_hour: 10,
          max_tx_per_day: 50,
        }).success
      ).toBe(false);
    });
  });

  describe('DestinationModeSchema', () => {
    it('should accept valid modes', () => {
      expect(DestinationModeSchema.safeParse('allowlist').success).toBe(true);
      expect(DestinationModeSchema.safeParse('blocklist').success).toBe(true);
      expect(DestinationModeSchema.safeParse('open').success).toBe(true);
    });

    it('should reject invalid modes', () => {
      expect(DestinationModeSchema.safeParse('whitelist').success).toBe(false);
      expect(DestinationModeSchema.safeParse('').success).toBe(false);
    });
  });

  describe('PolicyDestinationsSchema', () => {
    it('should accept valid destination configuration', () => {
      const validConfig = {
        mode: 'allowlist' as const,
        allowlist: ['rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh'],
        blocklist: [],
        allow_new_destinations: false,
      };

      expect(PolicyDestinationsSchema.safeParse(validConfig).success).toBe(true);
    });

    it('should accept open mode configuration', () => {
      const openConfig = {
        mode: 'open' as const,
        blocklist: ['rN7n3473SaZBCG4dFL83w7a1RXtXtbk2D9'], // valid XRPL address
        allow_new_destinations: true,
        new_destination_tier: 2 as const,
      };

      expect(PolicyDestinationsSchema.safeParse(openConfig).success).toBe(true);
    });
  });

  describe('PolicyTransactionTypesSchema', () => {
    it('should accept valid transaction type configuration', () => {
      const config = {
        allowed: ['Payment', 'EscrowFinish', 'EscrowCancel'] as const,
        require_approval: ['EscrowCreate', 'TrustSet'] as const,
        blocked: ['SetRegularKey', 'SignerListSet', 'AccountDelete'] as const,
      };

      expect(PolicyTransactionTypesSchema.safeParse(config).success).toBe(true);
    });

    it('should require at least one allowed type', () => {
      const config = {
        allowed: [],
        require_approval: ['Payment'],
      };

      expect(PolicyTransactionTypesSchema.safeParse(config).success).toBe(false);
    });
  });

  describe('PolicyTimeControlsSchema', () => {
    it('should accept valid time controls', () => {
      const config = {
        active_hours_utc: { start: 9, end: 17 },
        active_days: [1, 2, 3, 4, 5], // Monday-Friday
        timezone: 'America/New_York',
      };

      expect(PolicyTimeControlsSchema.safeParse(config).success).toBe(true);
    });

    it('should accept empty time controls', () => {
      expect(PolicyTimeControlsSchema.safeParse({}).success).toBe(true);
    });

    it('should reject invalid hours', () => {
      const config = {
        active_hours_utc: { start: 25, end: 17 }, // invalid start
      };

      expect(PolicyTimeControlsSchema.safeParse(config).success).toBe(false);
    });
  });

  describe('PolicyEscalationSchema', () => {
    it('should accept valid escalation configuration', () => {
      const config = {
        amount_threshold_drops: '10000000',
        new_destination: 3 as const,
        account_settings: 3 as const,
        delay_seconds: 300,
      };

      expect(PolicyEscalationSchema.safeParse(config).success).toBe(true);
    });

    it('should enforce account_settings is always tier 3', () => {
      const config = {
        amount_threshold_drops: '10000000',
        new_destination: 2 as const,
        account_settings: 2, // should be 3
        delay_seconds: 300,
      };

      expect(PolicyEscalationSchema.safeParse(config).success).toBe(false);
    });
  });

  describe('PolicyNotificationsSchema', () => {
    it('should accept valid HTTPS webhook URL', () => {
      const config = {
        webhook_url: 'https://example.com/webhook',
        notify_on: ['tier2', 'tier3', 'rejection'] as const,
      };

      expect(PolicyNotificationsSchema.safeParse(config).success).toBe(true);
    });

    it('should accept localhost for development', () => {
      const config = {
        webhook_url: 'http://localhost:3000/webhook',
        notify_on: ['all'] as const,
      };

      expect(PolicyNotificationsSchema.safeParse(config).success).toBe(true);
    });

    it('should reject non-HTTPS URLs', () => {
      const config = {
        webhook_url: 'http://example.com/webhook',
        notify_on: ['all'] as const,
      };

      expect(PolicyNotificationsSchema.safeParse(config).success).toBe(false);
    });
  });

  describe('AgentWalletPolicySchema', () => {
    const validPolicy = {
      policy_id: 'conservative-v1',
      policy_version: '1.0.0',
      limits: {
        max_amount_per_tx_drops: '10000000',
        max_daily_volume_drops: '50000000',
        max_tx_per_hour: 5,
        max_tx_per_day: 20,
      },
      destinations: {
        mode: 'allowlist' as const,
        allowlist: [],
        blocklist: [],
        allow_new_destinations: false,
      },
      transaction_types: {
        allowed: ['Payment', 'EscrowFinish', 'EscrowCancel'] as const,
        require_approval: ['EscrowCreate', 'TrustSet'] as const,
        blocked: ['SetRegularKey', 'SignerListSet', 'AccountSet', 'AccountDelete'] as const,
      },
      escalation: {
        amount_threshold_drops: '10000000',
        new_destination: 3 as const,
        account_settings: 3 as const,
        delay_seconds: 300,
      },
    };

    it('should accept valid complete policy', () => {
      const result = AgentWalletPolicySchema.safeParse(validPolicy);
      expect(result.success).toBe(true);
    });

    it('should accept policy with optional fields', () => {
      const policyWithOptionals = {
        ...validPolicy,
        time_controls: {
          active_hours_utc: { start: 9, end: 17 },
          active_days: [1, 2, 3, 4, 5],
        },
        notifications: {
          webhook_url: 'https://example.com/webhook',
          notify_on: ['tier2', 'tier3'] as const,
        },
      };

      expect(AgentWalletPolicySchema.safeParse(policyWithOptionals).success).toBe(true);
    });

    it('should reject invalid policy_id format', () => {
      const invalidPolicy = {
        ...validPolicy,
        policy_id: 'Invalid Policy ID', // contains spaces and uppercase
      };

      expect(AgentWalletPolicySchema.safeParse(invalidPolicy).success).toBe(false);
    });

    it('should reject invalid version format', () => {
      const invalidPolicy = {
        ...validPolicy,
        policy_version: 'v1.0.0', // should not have 'v' prefix
      };

      expect(AgentWalletPolicySchema.safeParse(invalidPolicy).success).toBe(false);
    });
  });
});

// ============================================================================
// MCP TOOL INPUT SCHEMA TESTS
// ============================================================================

describe('MCP Tool Input Schemas', () => {
  describe('WalletCreateInputSchema', () => {
    const validPolicy = {
      policy_id: 'test-policy',
      policy_version: '1.0',
      limits: {
        max_amount_per_tx_drops: '10000000',
        max_daily_volume_drops: '50000000',
        max_tx_per_hour: 5,
        max_tx_per_day: 20,
      },
      destinations: {
        mode: 'open' as const,
        allow_new_destinations: true,
      },
      transaction_types: {
        allowed: ['Payment'] as const,
      },
      escalation: {
        amount_threshold_drops: '10000000',
        new_destination: 2 as const,
        account_settings: 3 as const,
      },
    };

    it('should accept valid create input', () => {
      const input = {
        network: 'testnet' as const,
        policy: validPolicy,
        wallet_name: 'My Agent Wallet',
      };

      expect(WalletCreateInputSchema.safeParse(input).success).toBe(true);
    });

    it('should accept input with funding options', () => {
      const input = {
        network: 'mainnet' as const,
        policy: validPolicy,
        funding_source: 'rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh',
        initial_funding_drops: '20000000',
      };

      expect(WalletCreateInputSchema.safeParse(input).success).toBe(true);
    });
  });

  describe('WalletSignInputSchema', () => {
    it('should accept valid sign input', () => {
      const input = {
        wallet_address: 'rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh',
        unsigned_tx: 'A'.repeat(100), // valid hex
        context: 'Processing escrow for order #12345',
      };

      expect(WalletSignInputSchema.safeParse(input).success).toBe(true);
    });

    it('should accept sign input without context', () => {
      const input = {
        wallet_address: 'rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh',
        unsigned_tx: 'A'.repeat(100),
      };

      expect(WalletSignInputSchema.safeParse(input).success).toBe(true);
    });

    it('should reject invalid transaction blob', () => {
      const input = {
        wallet_address: 'rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh',
        unsigned_tx: 'A'.repeat(10), // too short
      };

      expect(WalletSignInputSchema.safeParse(input).success).toBe(false);
    });
  });

  describe('WalletBalanceInputSchema', () => {
    it('should accept valid balance input', () => {
      const input = {
        wallet_address: 'rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh',
      };

      expect(WalletBalanceInputSchema.safeParse(input).success).toBe(true);
    });
  });

  describe('WalletPolicyCheckInputSchema', () => {
    it('should accept valid policy check input', () => {
      const input = {
        wallet_address: 'rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh',
        unsigned_tx: 'A'.repeat(100),
      };

      expect(WalletPolicyCheckInputSchema.safeParse(input).success).toBe(true);
    });
  });

  describe('WalletHistoryInputSchema', () => {
    it('should accept valid history input with defaults', () => {
      const input = {
        wallet_address: 'rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh',
      };

      const result = WalletHistoryInputSchema.safeParse(input);
      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.data.limit).toBe(20); // default
      }
    });

    it('should accept valid history input with pagination', () => {
      const input = {
        wallet_address: 'rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh',
        limit: 50,
        marker: 'next-page-marker',
      };

      expect(WalletHistoryInputSchema.safeParse(input).success).toBe(true);
    });

    it('should reject limit exceeding maximum', () => {
      const input = {
        wallet_address: 'rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh',
        limit: 200, // exceeds max of 100
      };

      expect(WalletHistoryInputSchema.safeParse(input).success).toBe(false);
    });
  });

  describe('WalletFundInputSchema', () => {
    it('should accept testnet funding', () => {
      const input = {
        wallet_address: 'rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh',
        network: 'testnet' as const,
      };

      expect(WalletFundInputSchema.safeParse(input).success).toBe(true);
    });

    it('should accept devnet funding', () => {
      const input = {
        wallet_address: 'rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh',
        network: 'devnet' as const,
      };

      expect(WalletFundInputSchema.safeParse(input).success).toBe(true);
    });

    it('should reject mainnet funding', () => {
      const input = {
        wallet_address: 'rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh',
        network: 'mainnet',
      };

      expect(WalletFundInputSchema.safeParse(input).success).toBe(false);
    });
  });

  describe('TxSubmitInputSchema', () => {
    it('should accept valid submit input', () => {
      const input = {
        signed_tx: 'A'.repeat(200),
        network: 'testnet' as const,
      };

      const result = TxSubmitInputSchema.safeParse(input);
      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.data.wait_for_validation).toBe(true); // default
      }
    });

    it('should accept submit without waiting', () => {
      const input = {
        signed_tx: 'A'.repeat(200),
        network: 'mainnet' as const,
        wait_for_validation: false,
      };

      expect(TxSubmitInputSchema.safeParse(input).success).toBe(true);
    });
  });

  describe('NetworkConfigInputSchema', () => {
    it('should accept valid network config', () => {
      const input = {
        network: 'mainnet' as const,
        primary_url: 'wss://xrplcluster.com/',
        fallback_urls: ['wss://s1.ripple.com/', 'wss://s2.ripple.com/'],
        connection_timeout_ms: 10000,
      };

      expect(NetworkConfigInputSchema.safeParse(input).success).toBe(true);
    });

    it('should accept localhost for development', () => {
      const input = {
        network: 'devnet' as const,
        primary_url: 'ws://localhost:6006',
      };

      expect(NetworkConfigInputSchema.safeParse(input).success).toBe(true);
    });

    it('should reject non-secure WebSocket URLs', () => {
      const input = {
        network: 'mainnet' as const,
        primary_url: 'ws://xrplcluster.com/', // should be wss
      };

      expect(NetworkConfigInputSchema.safeParse(input).success).toBe(false);
    });
  });
});

// ============================================================================
// MCP TOOL OUTPUT SCHEMA TESTS
// ============================================================================

describe('MCP Tool Output Schemas', () => {
  describe('WalletSignOutputSchema (discriminated union)', () => {
    it('should accept approved output', () => {
      const output = {
        status: 'approved' as const,
        signed_tx: 'A'.repeat(200),
        tx_hash: 'A'.repeat(64),
        policy_tier: 1 as const,
        limits_after: {
          daily_remaining_drops: '40000000',
          hourly_tx_remaining: 4,
          daily_tx_remaining: 19,
        },
        signed_at: '2026-01-28T14:30:00Z',
      };

      const result = WalletSignOutputSchema.safeParse(output);
      expect(result.success).toBe(true);
    });

    it('should accept pending output', () => {
      const output = {
        status: 'pending_approval' as const,
        approval_id: 'approval-123',
        reason: 'exceeds_autonomous_limit' as const,
        expires_at: '2026-01-28T15:00:00Z',
        policy_tier: 2 as const,
      };

      expect(WalletSignOutputSchema.safeParse(output).success).toBe(true);
    });

    it('should accept rejected output', () => {
      const output = {
        status: 'rejected' as const,
        reason: 'Transaction exceeds daily volume limit',
        policy_violation: {
          rule: 'daily_volume_limit',
          limit: '50000000',
          actual: '60000000',
        },
        policy_tier: 4 as const,
      };

      expect(WalletSignOutputSchema.safeParse(output).success).toBe(true);
    });

    it('should discriminate correctly', () => {
      // Approved with wrong fields should fail
      const mixedOutput = {
        status: 'approved' as const,
        approval_id: 'approval-123', // wrong field for approved
      };

      expect(WalletSignOutputSchema.safeParse(mixedOutput).success).toBe(false);
    });
  });

  describe('WalletBalanceOutputSchema', () => {
    it('should accept valid balance output', () => {
      const output = {
        address: 'rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh',
        balance_drops: '50000000',
        balance_xrp: '50.0',
        reserve_drops: '10000000',
        available_drops: '40000000',
        sequence: 1,
        regular_key_set: true,
        signer_list: null,
        policy_id: 'conservative-v1',
        network: 'mainnet' as const,
        ledger_index: 12345678,
        queried_at: '2026-01-28T14:30:00Z',
      };

      expect(WalletBalanceOutputSchema.safeParse(output).success).toBe(true);
    });

    it('should accept balance with signer list', () => {
      const output = {
        address: 'rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh',
        balance_drops: '50000000',
        balance_xrp: '50.0',
        reserve_drops: '12000000',
        available_drops: '38000000',
        sequence: 100,
        regular_key_set: false,
        signer_list: [
          { account: 'rN7n3473SaZBCG4dFL83w7a1RXtXtbk2D9', weight: 1 },
          { account: 'rf1BiGeXwwQoi8Z2ueFYTEXSwuJYfV2Jpn', weight: 2 },
        ],
        policy_id: 'multisig-v1',
        network: 'mainnet' as const,
        ledger_index: 12345678,
        queried_at: '2026-01-28T14:30:00Z',
      };

      expect(WalletBalanceOutputSchema.safeParse(output).success).toBe(true);
    });
  });

  describe('WalletPolicyCheckOutputSchema', () => {
    it('should accept valid policy check output', () => {
      const output = {
        would_approve: true,
        tier: 1 as const,
        warnings: ['Approaching daily limit (80% used)'],
        violations: [],
        limits: {
          daily_volume_used_drops: '40000000',
          daily_volume_limit_drops: '50000000',
          hourly_tx_used: 3,
          hourly_tx_limit: 5,
          daily_tx_used: 15,
          daily_tx_limit: 20,
        },
        transaction_details: {
          type: 'Payment' as const,
          destination: 'rN7n3473SaZBCG4dFL83w7a1RXtXtbk2D9',
          amount_drops: '5000000',
        },
      };

      expect(WalletPolicyCheckOutputSchema.safeParse(output).success).toBe(true);
    });

    it('should accept denied policy check output', () => {
      const output = {
        would_approve: false,
        tier: 4 as const,
        warnings: [],
        violations: ['Transaction type blocked: SetRegularKey'],
        limits: {
          daily_volume_used_drops: '0',
          daily_volume_limit_drops: '50000000',
          hourly_tx_used: 0,
          hourly_tx_limit: 5,
          daily_tx_used: 0,
          daily_tx_limit: 20,
        },
      };

      expect(WalletPolicyCheckOutputSchema.safeParse(output).success).toBe(true);
    });
  });
});

// ============================================================================
// ERROR SCHEMA TESTS
// ============================================================================

describe('Error Schemas', () => {
  describe('ErrorCodeSchema', () => {
    it('should accept all valid error codes', () => {
      const validCodes = [
        'VALIDATION_ERROR',
        'POLICY_VIOLATION',
        'WALLET_NOT_FOUND',
        'NETWORK_ERROR',
        'INTERNAL_ERROR',
        'INSUFFICIENT_BALANCE',
      ];

      for (const code of validCodes) {
        expect(ErrorCodeSchema.safeParse(code).success).toBe(true);
      }
    });

    it('should reject invalid error codes', () => {
      expect(ErrorCodeSchema.safeParse('UNKNOWN_ERROR').success).toBe(false);
      expect(ErrorCodeSchema.safeParse('').success).toBe(false);
    });
  });

  describe('ErrorResponseSchema', () => {
    it('should accept valid error response', () => {
      const error = {
        code: 'POLICY_VIOLATION' as const,
        message: 'Transaction exceeds maximum amount per transaction',
        details: {
          limit: '10000000',
          actual: '50000000',
        },
        request_id: 'req-123-abc',
        timestamp: '2026-01-28T14:30:00Z',
      };

      expect(ErrorResponseSchema.safeParse(error).success).toBe(true);
    });

    it('should accept minimal error response', () => {
      const error = {
        code: 'INTERNAL_ERROR' as const,
        message: 'An unexpected error occurred',
        timestamp: '2026-01-28T14:30:00Z',
      };

      expect(ErrorResponseSchema.safeParse(error).success).toBe(true);
    });
  });
});

// ============================================================================
// AUDIT LOG SCHEMA TESTS
// ============================================================================

describe('Audit Log Schemas', () => {
  describe('AuditEventTypeSchema', () => {
    it('should accept all valid event types', () => {
      const eventTypes = [
        'wallet_created',
        'transaction_signed',
        'policy_evaluated',
        'approval_requested',
        'rate_limit_triggered',
        'server_started',
      ];

      for (const type of eventTypes) {
        expect(AuditEventTypeSchema.safeParse(type).success).toBe(true);
      }
    });
  });

  describe('AuditLogEntrySchema', () => {
    it('should accept valid audit log entry', () => {
      const entry = {
        seq: 12345,
        timestamp: '2026-01-28T14:30:00.123Z',
        event: 'transaction_signed' as const,
        wallet_id: 'agent-wallet-001',
        wallet_address: 'rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh',
        transaction_type: 'Payment' as const,
        amount_xrp: '50.0',
        destination: 'rN7n3473SaZBCG4dFL83w7a1RXtXtbk2D9',
        tier: 1 as const,
        policy_decision: 'allowed' as const,
        tx_hash: 'A'.repeat(64),
        context: 'Processing escrow for order #12345',
        prev_hash: 'B'.repeat(64),
        hash: 'C'.repeat(64),
      };

      expect(AuditLogEntrySchema.safeParse(entry).success).toBe(true);
    });

    it('should accept minimal audit log entry', () => {
      const entry = {
        seq: 0,
        timestamp: '2026-01-28T14:30:00Z',
        event: 'server_started' as const,
        prev_hash: 'genesis',
        hash: 'A'.repeat(64),
      };

      expect(AuditLogEntrySchema.safeParse(entry).success).toBe(true);
    });
  });
});

// ============================================================================
// TYPE INFERENCE TESTS
// ============================================================================

describe('Type Inference', () => {
  it('should correctly infer XRPLAddress type', () => {
    const address = XRPLAddressSchema.parse('rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh');
    expectTypeOf(address).toEqualTypeOf<XRPLAddress>();
    expectTypeOf(address).toEqualTypeOf<string>();
  });

  it('should correctly infer DropsAmount type', () => {
    const amount = DropsAmountSchema.parse('1000000');
    expectTypeOf(amount).toEqualTypeOf<DropsAmount>();
    expectTypeOf(amount).toEqualTypeOf<string>();
  });

  it('should correctly infer TransactionHash type', () => {
    const hash = TransactionHashSchema.parse('A'.repeat(64));
    expectTypeOf(hash).toEqualTypeOf<TransactionHash>();
    expectTypeOf(hash).toEqualTypeOf<string>();
  });

  it('should correctly infer Network type', () => {
    const network = NetworkSchema.parse('mainnet');
    expectTypeOf(network).toEqualTypeOf<Network>();
    expectTypeOf(network).toEqualTypeOf<'mainnet' | 'testnet' | 'devnet'>();
  });

  it('should correctly infer AgentWalletPolicy type', () => {
    const policy: AgentWalletPolicy = {
      policy_id: 'test',
      policy_version: '1.0',
      limits: {
        max_amount_per_tx_drops: '1000000',
        max_daily_volume_drops: '10000000',
        max_tx_per_hour: 5,
        max_tx_per_day: 20,
      },
      destinations: {
        mode: 'open',
        allow_new_destinations: true,
      },
      transaction_types: {
        allowed: ['Payment'],
      },
      escalation: {
        amount_threshold_drops: '1000000',
        new_destination: 2,
        account_settings: 3,
      },
    };

    expectTypeOf(policy).toMatchTypeOf<AgentWalletPolicy>();
  });

  it('should correctly infer discriminated union WalletSignOutput', () => {
    const approved: WalletSignOutput = {
      status: 'approved',
      signed_tx: 'A'.repeat(200),
      tx_hash: 'A'.repeat(64),
      policy_tier: 1,
      limits_after: {
        daily_remaining_drops: '1000000',
        hourly_tx_remaining: 5,
        daily_tx_remaining: 20,
      },
      signed_at: '2026-01-28T14:30:00Z',
    };

    const pending: WalletSignOutput = {
      status: 'pending_approval',
      approval_id: 'test',
      reason: 'exceeds_autonomous_limit',
      expires_at: '2026-01-28T15:00:00Z',
      policy_tier: 2,
    };

    const rejected: WalletSignOutput = {
      status: 'rejected',
      reason: 'Policy violation',
      policy_tier: 4,
    };

    expectTypeOf(approved).toMatchTypeOf<WalletSignOutput>();
    expectTypeOf(pending).toMatchTypeOf<WalletSignOutput>();
    expectTypeOf(rejected).toMatchTypeOf<WalletSignOutput>();
  });
});
