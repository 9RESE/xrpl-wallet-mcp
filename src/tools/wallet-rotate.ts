/**
 * wallet_rotate Tool Implementation
 *
 * Rotates the agent wallet signing key by setting a new regular key on-chain.
 *
 * Security Process:
 * 1. Generate new key pair locally
 * 2. Build SetRegularKey transaction with new public key
 * 3. Sign with current key
 * 4. Submit to XRPL and wait for validation
 * 5. Update keystore metadata
 * 6. Audit the rotation event
 *
 * @module tools/wallet-rotate
 * @version 1.0.0
 */

import { Wallet, type SetRegularKey } from 'xrpl';
import type { ServerContext } from '../server.js';
import type { WalletRotateInput, WalletRotateOutput } from '../schemas/index.js';
import { getWalletPassword } from '../utils/env.js';

/**
 * Handle wallet_rotate tool invocation.
 *
 * SECURITY: This is a CRITICAL operation. After rotation:
 * - The old regular key is disabled on-chain
 * - Only the new regular key can sign transactions
 * - The master key remains unchanged (for recovery)
 *
 * @param context - Service instances
 * @param input - Validated rotation request
 * @returns Rotation result with new public key and transaction hash
 */
export async function handleWalletRotate(
  context: ServerContext,
  input: WalletRotateInput
): Promise<WalletRotateOutput> {
  const { keystore, signingService, xrplClient, auditLogger } = context;

  // Step 1: Get wallet entry
  const wallets = await keystore.listWallets();
  const wallet = wallets.find((w) => w.address === input.wallet_address);

  if (!wallet) {
    throw new Error(`Wallet not found: ${input.wallet_address}`);
  }

  // Step 2: Generate new regular key pair
  // Using Ed25519 for better performance and security
  const newRegularKeyWallet = Wallet.generate();

  // Step 3: Get current account info for sequence number
  const accountInfo = await xrplClient.getAccountInfo(input.wallet_address);

  // Step 4: Get current fee
  const fee = await xrplClient.getFee();

  // Step 5: Build SetRegularKey transaction
  const setRegularKeyTx: SetRegularKey = {
    TransactionType: 'SetRegularKey',
    Account: input.wallet_address,
    RegularKey: newRegularKeyWallet.classicAddress,
    Sequence: accountInfo.sequence,
    Fee: fee,
  };

  // Step 6: Sign with current wallet key
  const password = getWalletPassword();
  const signed = await signingService.sign(wallet.walletId, setRegularKeyTx, password);

  // Step 7: Submit to XRPL and wait for validation
  const result = await xrplClient.submitSignedTransaction(signed.tx_blob, {
    waitForValidation: true,
    timeout: 30000, // 30 seconds
  });

  if (!result.validated) {
    throw new Error(`SetRegularKey transaction not validated: ${result.resultCode}`);
  }

  const timestamp = new Date().toISOString();

  // Step 8: Store the new regular key in the keystore
  // This allows the signing service to use the regular key instead of master key
  if ('storeRegularKey' in keystore) {
    const keystoreWithRegularKey = keystore as typeof keystore & {
      storeRegularKey: (
        walletId: string,
        seed: string,
        address: string,
        password: string
      ) => Promise<void>;
    };

    await keystoreWithRegularKey.storeRegularKey(
      wallet.walletId,
      newRegularKeyWallet.seed!,
      newRegularKeyWallet.classicAddress,
      password
    );
  }

  // Step 9: Update wallet metadata to reflect the rotation
  await keystore.updateMetadata(wallet.walletId, {
    hasRegularKey: true,
    lastUsedAt: timestamp,
    customData: {
      ...(wallet as any).customData,
      regularKeyAddress: newRegularKeyWallet.classicAddress,
      regularKeyPublic: newRegularKeyWallet.publicKey,
      lastRotatedAt: timestamp,
      rotationReason: input.reason || 'Manual rotation',
      rotationTxHash: result.hash,
    },
  });

  // Step 10: Audit key rotation
  await auditLogger.log({
    event: 'key_rotated',
    wallet_id: wallet.walletId,
    wallet_address: wallet.address,
    context: JSON.stringify({
      reason: input.reason || 'Manual rotation',
      new_regular_key_address: newRegularKeyWallet.classicAddress,
      rotation_tx_hash: result.hash,
    }),
  });

  return {
    status: 'rotated',
    new_regular_key_public: newRegularKeyWallet.publicKey,
    old_key_disabled: true,
    rotation_tx_hash: result.hash,
    rotated_at: timestamp,
  };
}
