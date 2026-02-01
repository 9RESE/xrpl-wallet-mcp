#!/usr/bin/env npx ts-node
/**
 * Test newer XRPL transaction types on testnet
 *
 * Tests Oracle, DID, and other newer features
 */

import * as xrpl from 'xrpl';

const TESTNET_URL = 'wss://s.altnet.rippletest.net:51233';

function log(msg: string) {
  console.log(`[TEST] ${msg}`);
}

async function testOracleSet(client: xrpl.Client, wallet: xrpl.Wallet) {
  log('Testing OracleSet (Price Oracle)...');

  try {
    // OracleSet transaction
    const oracleTx = {
      TransactionType: 'OracleSet',
      Account: wallet.address,
      OracleDocumentID: 1,
      Provider: Buffer.from('TestProvider').toString('hex').toUpperCase(),
      AssetClass: Buffer.from('currency').toString('hex').toUpperCase(),
      LastUpdateTime: Math.floor(Date.now() / 1000),
      PriceDataSeries: [
        {
          PriceData: {
            BaseAsset: 'XRP',
            QuoteAsset: 'USD',
            AssetPrice: 50000, // $0.50 in scaled format
            Scale: 5,
          },
        },
      ],
    };

    const prepared = await client.autofill(oracleTx);
    const signed = wallet.sign(prepared);
    const result = await client.submitAndWait(signed.tx_blob);

    const meta = result.result.meta as { TransactionResult?: string };
    log(`  OracleSet result: ${meta?.TransactionResult}`);

    if (meta?.TransactionResult === 'tesSUCCESS') {
      console.log('✅ OracleSet: Created price oracle successfully');
    } else if (meta?.TransactionResult?.startsWith('tec')) {
      console.log(`⚠️ OracleSet: ${meta?.TransactionResult} (tx format valid, execution issue)`);
    } else {
      console.log(`❌ OracleSet: ${meta?.TransactionResult}`);
    }
  } catch (error: any) {
    if (error.message?.includes('amendmentBlocked') || error.message?.includes('PriceOracle')) {
      console.log('⚠️ OracleSet: PriceOracle amendment may not be enabled on testnet');
    } else {
      console.log(`❌ OracleSet: ${error.message || error}`);
    }
  }
}

async function testDIDSet(client: xrpl.Client, wallet: xrpl.Wallet) {
  log('Testing DIDSet (Decentralized Identifier)...');

  try {
    const didTx = {
      TransactionType: 'DIDSet',
      Account: wallet.address,
      Data: Buffer.from('test-did-data').toString('hex').toUpperCase(),
      DIDDocument: Buffer.from('{"id":"did:xrpl:test"}').toString('hex').toUpperCase(),
      URI: Buffer.from('https://example.com/did').toString('hex').toUpperCase(),
    };

    const prepared = await client.autofill(didTx);
    const signed = wallet.sign(prepared);
    const result = await client.submitAndWait(signed.tx_blob);

    const meta = result.result.meta as { TransactionResult?: string };
    log(`  DIDSet result: ${meta?.TransactionResult}`);

    if (meta?.TransactionResult === 'tesSUCCESS') {
      console.log('✅ DIDSet: Created DID successfully');
    } else {
      console.log(`⚠️ DIDSet: ${meta?.TransactionResult}`);
    }
  } catch (error: any) {
    if (error.message?.includes('amendmentBlocked') || error.message?.includes('DID')) {
      console.log('⚠️ DIDSet: DID amendment may not be enabled on testnet');
    } else {
      console.log(`❌ DIDSet: ${error.message || error}`);
    }
  }
}

async function testPaymentChannel(client: xrpl.Client, wallet: xrpl.Wallet) {
  log('Testing PaymentChannelCreate...');

  try {
    const channelTx: xrpl.PaymentChannelCreate = {
      TransactionType: 'PaymentChannelCreate',
      Account: wallet.address,
      Destination: wallet.address, // Self for testing
      Amount: '10000000', // 10 XRP
      SettleDelay: 86400, // 1 day
      PublicKey: wallet.publicKey,
    };

    const prepared = await client.autofill(channelTx);
    const signed = wallet.sign(prepared);
    const result = await client.submitAndWait(signed.tx_blob);

    const meta = result.result.meta as { TransactionResult?: string };
    log(`  PaymentChannelCreate result: ${meta?.TransactionResult}`);

    if (meta?.TransactionResult === 'tesSUCCESS') {
      console.log('✅ PaymentChannelCreate: Created payment channel successfully');
    } else {
      console.log(`⚠️ PaymentChannelCreate: ${meta?.TransactionResult}`);
    }
  } catch (error: any) {
    console.log(`❌ PaymentChannelCreate: ${error.message || error}`);
  }
}

async function testNFTokenMint(client: xrpl.Client, wallet: xrpl.Wallet) {
  log('Testing NFTokenMint...');

  try {
    const nftTx: xrpl.NFTokenMint = {
      TransactionType: 'NFTokenMint',
      Account: wallet.address,
      NFTokenTaxon: 0,
      Flags: 8, // tfTransferable
      URI: Buffer.from('https://example.com/nft/1').toString('hex').toUpperCase(),
    };

    const prepared = await client.autofill(nftTx);
    const signed = wallet.sign(prepared);
    const result = await client.submitAndWait(signed.tx_blob);

    const meta = result.result.meta as { TransactionResult?: string };
    log(`  NFTokenMint result: ${meta?.TransactionResult}`);

    if (meta?.TransactionResult === 'tesSUCCESS') {
      console.log('✅ NFTokenMint: Minted NFT successfully');
    } else {
      console.log(`⚠️ NFTokenMint: ${meta?.TransactionResult}`);
    }
  } catch (error: any) {
    console.log(`❌ NFTokenMint: ${error.message || error}`);
  }
}

async function testDepositPreauth(client: xrpl.Client, wallet: xrpl.Wallet, otherWallet: xrpl.Wallet) {
  log('Testing DepositPreauth...');

  try {
    const preauthTx: xrpl.DepositPreauth = {
      TransactionType: 'DepositPreauth',
      Account: wallet.address,
      Authorize: otherWallet.address,
    };

    const prepared = await client.autofill(preauthTx);
    const signed = wallet.sign(prepared);
    const result = await client.submitAndWait(signed.tx_blob);

    const meta = result.result.meta as { TransactionResult?: string };
    log(`  DepositPreauth result: ${meta?.TransactionResult}`);

    if (meta?.TransactionResult === 'tesSUCCESS') {
      console.log('✅ DepositPreauth: Authorized deposit from other wallet');
    } else {
      console.log(`⚠️ DepositPreauth: ${meta?.TransactionResult}`);
    }
  } catch (error: any) {
    console.log(`❌ DepositPreauth: ${error.message || error}`);
  }
}

async function testSignerListSet(client: xrpl.Client, wallet: xrpl.Wallet, signer: xrpl.Wallet) {
  log('Testing SignerListSet (multi-sig)...');

  try {
    const signerTx: xrpl.SignerListSet = {
      TransactionType: 'SignerListSet',
      Account: wallet.address,
      SignerQuorum: 1,
      SignerEntries: [
        {
          SignerEntry: {
            Account: signer.address,
            SignerWeight: 1,
          },
        },
      ],
    };

    const prepared = await client.autofill(signerTx);
    const signed = wallet.sign(prepared);
    const result = await client.submitAndWait(signed.tx_blob);

    const meta = result.result.meta as { TransactionResult?: string };
    log(`  SignerListSet result: ${meta?.TransactionResult}`);

    if (meta?.TransactionResult === 'tesSUCCESS') {
      console.log('✅ SignerListSet: Created signer list (1-of-1 multisig)');
    } else {
      console.log(`⚠️ SignerListSet: ${meta?.TransactionResult}`);
    }
  } catch (error: any) {
    console.log(`❌ SignerListSet: ${error.message || error}`);
  }
}

async function showFinalState(client: xrpl.Client, wallet: xrpl.Wallet) {
  log('');
  log('═══════════════════════════════════════════');
  log('           FINAL ACCOUNT STATE');
  log('═══════════════════════════════════════════');

  try {
    const accountInfo = await client.request({
      command: 'account_info',
      account: wallet.address,
      ledger_index: 'validated'
    });

    const ownerCount = accountInfo.result.account_data.OwnerCount;
    const balance = Number(accountInfo.result.account_data.Balance) / 1_000_000;

    const serverInfo = await client.request({ command: 'server_info' });
    const ledger = serverInfo.result.info.validated_ledger;

    if (ledger) {
      const baseReserve = ledger.reserve_base_xrp;
      const ownerReserve = ledger.reserve_inc_xrp;
      const totalReserve = baseReserve + (ownerCount * ownerReserve);
      const available = balance - totalReserve;

      log(`  Address: ${wallet.address}`);
      log(`  Balance: ${balance.toFixed(6)} XRP`);
      log(`  Owner Count: ${ownerCount} objects`);
      log(`  Reserve: ${totalReserve.toFixed(1)} XRP (${baseReserve} + ${ownerCount} × ${ownerReserve})`);
      log(`  Available: ${available.toFixed(6)} XRP`);
    }

    // List account objects
    const objects = await client.request({
      command: 'account_objects',
      account: wallet.address,
      ledger_index: 'validated'
    });

    log('');
    log('  Owned Objects:');
    const typeCounts: Record<string, number> = {};
    for (const obj of objects.result.account_objects) {
      const type = obj.LedgerEntryType;
      typeCounts[type] = (typeCounts[type] || 0) + 1;
    }
    for (const [type, count] of Object.entries(typeCounts)) {
      log(`    - ${type}: ${count}`);
    }

  } catch (error) {
    log(`  Error getting final state: ${error}`);
  }

  log('═══════════════════════════════════════════');
}

async function main() {
  console.log('');
  console.log('╔═══════════════════════════════════════════════════════════╗');
  console.log('║    XRPL New Transaction Types Test - Testnet              ║');
  console.log('╚═══════════════════════════════════════════════════════════╝');
  console.log('');

  const client = new xrpl.Client(TESTNET_URL);

  try {
    log('Connecting to testnet...');
    await client.connect();
    log('Connected!\n');

    // Create and fund main wallet
    log('Creating and funding test wallet...');
    const wallet = xrpl.Wallet.generate();
    await client.fundWallet(wallet);
    log(`  Main wallet: ${wallet.address}\n`);

    // Create second wallet for tests that need another account
    log('Creating second wallet for multi-account tests...');
    const wallet2 = xrpl.Wallet.generate();
    await client.fundWallet(wallet2);
    log(`  Second wallet: ${wallet2.address}\n`);

    // Run tests
    await testPaymentChannel(client, wallet);
    console.log('');

    await testNFTokenMint(client, wallet);
    console.log('');

    await testDepositPreauth(client, wallet, wallet2);
    console.log('');

    await testSignerListSet(client, wallet, wallet2);
    console.log('');

    await testDIDSet(client, wallet);
    console.log('');

    await testOracleSet(client, wallet);
    console.log('');

    await showFinalState(client, wallet);

  } catch (error) {
    console.error('Fatal error:', error);
  } finally {
    await client.disconnect();
  }
}

main();
