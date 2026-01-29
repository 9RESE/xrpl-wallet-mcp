/**
 * tx_decode Tool Implementation
 *
 * Decodes transaction blob for inspection.
 *
 * @module tools/tx-decode
 * @version 1.0.0
 */

import { decode, hashes } from 'xrpl';
import type { ServerContext } from '../server.js';
import type { TxDecodeInput, TxDecodeOutput } from '../schemas/index.js';

/**
 * Handle tx_decode tool invocation.
 *
 * Decodes a hex-encoded transaction blob into readable JSON.
 * Works with both signed and unsigned transactions.
 *
 * @param context - Service instances
 * @param input - Validated decode request
 * @returns Decoded transaction fields
 */
export async function handleTxDecode(
  _context: ServerContext,
  input: TxDecodeInput
): Promise<TxDecodeOutput> {
  // Decode transaction blob
  const decoded = decode(input.tx_blob);

  // Check if transaction is signed (has TxnSignature or Signers)
  const isSigned = 'TxnSignature' in decoded || 'Signers' in decoded;

  // Extract signing public key if signed (use bracket notation for index signature)
  const signingPubKeyField = 'SigningPubKey' in decoded ? decoded['SigningPubKey'] : undefined;
  const signingPublicKey = typeof signingPubKeyField === 'string' ? signingPubKeyField : undefined;

  // Calculate hash if signed
  let hash: string | undefined;
  if (isSigned) {
    try {
      hash = hashes.hashSignedTx(input.tx_blob);
    } catch {
      // Hash calculation failed - might be malformed
      hash = undefined;
    }
  }

  return {
    transaction: decoded as any, // Type assertion - decoded tx matches schema
    hash,
    is_signed: isSigned,
    signing_public_key: signingPublicKey,
  };
}
