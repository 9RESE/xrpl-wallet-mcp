/**
 * Signing Module - Transaction signing with multi-signature support.
 *
 * This module provides:
 * - SigningService: Single-signature transaction signing
 * - MultiSignOrchestrator: Multi-signature workflow coordination
 * - Secure key material handling with SecureBuffer
 * - XRPL native multi-signature support
 *
 * @module signing
 * @version 1.0.0
 */

// Export SigningService
export { SigningService, SigningError, type SignedTransaction } from './service.js';

// Export MultiSignOrchestrator
export {
  MultiSignOrchestrator,
  MultiSignError,
  type SignerConfig,
  type SignerListConfig,
  type MultiSignStatus,
  type SignerState,
  type MultiSignRequest,
  type MultiSignCompleteResult,
  type MultiSignStore,
  type NotificationService,
} from './multisig.js';
