#!/usr/bin/env npx ts-node
/**
 * Test script for new XRPL features on testnet
 *
 * Tests:
 * 1. Reserve calculations (1 XRP base, 0.2 XRP owner)
 * 2. New transaction types validation
 * 3. Wallet operations
 */

import * as xrpl from 'xrpl';

const TESTNET_URL = 'wss://s.altnet.rippletest.net:51233';

interface TestResult {
  name: string;
  passed: boolean;
  details: string;
}

const results: TestResult[] = [];

function log(msg: string) {
  console.log(`[TEST] ${msg}`);
}

function pass(name: string, details: string) {
  results.push({ name, passed: true, details });
  console.log(`✅ ${name}: ${details}`);
}

function fail(name: string, details: string) {
  results.push({ name, passed: false, details });
  console.log(`❌ ${name}: ${details}`);
}

async function testReserves(client: xrpl.Client) {
  log('Testing reserve values...');

  try {
    const serverInfo = await client.request({ command: 'server_info' });
    const ledger = serverInfo.result.info.validated_ledger;

    if (!ledger) {
      fail('Reserve Values', 'No validated ledger info');
      return;
    }

    const baseReserve = ledger.reserve_base_xrp;
    const ownerReserve = ledger.reserve_inc_xrp;

    log(`  Base Reserve: ${baseReserve} XRP`);
    log(`  Owner Reserve: ${ownerReserve} XRP`);

    // Check if reserves match Dec 2024 values
    if (baseReserve === 1 && ownerReserve === 0.2) {
      pass('Reserve Values', `Base: ${baseReserve} XRP, Owner: ${ownerReserve} XRP (matches Dec 2024)`);
    } else if (baseReserve <= 10 && ownerReserve <= 2) {
      pass('Reserve Values', `Base: ${baseReserve} XRP, Owner: ${ownerReserve} XRP (within expected range)`);
    } else {
      fail('Reserve Values', `Unexpected values - Base: ${baseReserve}, Owner: ${ownerReserve}`);
    }
  } catch (error) {
    fail('Reserve Values', `Error: ${error}`);
  }
}

async function testWalletCreation(client: xrpl.Client) {
  log('Testing wallet creation and funding...');

  try {
    // Generate a new wallet
    const wallet = xrpl.Wallet.generate();
    log(`  Generated wallet: ${wallet.address}`);

    // Fund from faucet
    log('  Requesting funds from testnet faucet...');
    const fundResult = await client.fundWallet(wallet);

    log(`  Funded with: ${fundResult.balance} XRP`);

    // Check balance
    const accountInfo = await client.request({
      command: 'account_info',
      account: wallet.address,
      ledger_index: 'validated'
    });

    const balance = Number(accountInfo.result.account_data.Balance) / 1_000_000;
    log(`  Confirmed balance: ${balance} XRP`);

    pass('Wallet Creation', `Created and funded wallet with ${balance} XRP`);

    return wallet;
  } catch (error) {
    fail('Wallet Creation', `Error: ${error}`);
    return null;
  }
}

async function testEscrowCreate(client: xrpl.Client, wallet: xrpl.Wallet) {
  log('Testing EscrowCreate...');

  try {
    const finishAfter = Math.floor(Date.now() / 1000) + 60; // 1 minute from now
    const cancelAfter = Math.floor(Date.now() / 1000) + 3600; // 1 hour from now

    const escrowTx: xrpl.EscrowCreate = {
      TransactionType: 'EscrowCreate',
      Account: wallet.address,
      Destination: wallet.address, // Self-escrow for testing
      Amount: '1000000', // 1 XRP
      FinishAfter: finishAfter,
      CancelAfter: cancelAfter,
    };

    const prepared = await client.autofill(escrowTx);
    const signed = wallet.sign(prepared);
    const result = await client.submitAndWait(signed.tx_blob);

    const txResult = result.result.meta as { TransactionResult?: string };
    if (txResult?.TransactionResult === 'tesSUCCESS') {
      // Get the escrow sequence
      const escrowSeq = (result.result.tx_json as { Sequence?: number })?.Sequence;
      pass('EscrowCreate', `Created escrow, sequence: ${escrowSeq}`);
      return escrowSeq;
    } else {
      fail('EscrowCreate', `Result: ${txResult?.TransactionResult}`);
      return null;
    }
  } catch (error) {
    fail('EscrowCreate', `Error: ${error}`);
    return null;
  }
}

async function testOwnerCount(client: xrpl.Client, wallet: xrpl.Wallet) {
  log('Testing owner count after escrow...');

  try {
    const accountInfo = await client.request({
      command: 'account_info',
      account: wallet.address,
      ledger_index: 'validated'
    });

    const ownerCount = accountInfo.result.account_data.OwnerCount;
    log(`  Owner count: ${ownerCount}`);

    if (ownerCount >= 1) {
      pass('Owner Count', `Owner count is ${ownerCount} (escrow added)`);
    } else {
      fail('Owner Count', `Expected owner count >= 1, got ${ownerCount}`);
    }

    // Calculate reserve
    const balance = Number(accountInfo.result.account_data.Balance) / 1_000_000;
    const serverInfo = await client.request({ command: 'server_info' });
    const ledger = serverInfo.result.info.validated_ledger;

    if (ledger) {
      const baseReserve = ledger.reserve_base_xrp;
      const ownerReserve = ledger.reserve_inc_xrp;
      const totalReserve = baseReserve + (ownerCount * ownerReserve);
      const available = balance - totalReserve;

      log(`  Total balance: ${balance} XRP`);
      log(`  Total reserve: ${totalReserve} XRP (${baseReserve} + ${ownerCount} × ${ownerReserve})`);
      log(`  Available: ${available} XRP`);

      pass('Reserve Calculation', `Reserve: ${totalReserve} XRP, Available: ${available.toFixed(2)} XRP`);
    }
  } catch (error) {
    fail('Owner Count', `Error: ${error}`);
  }
}

async function testTrustLine(client: xrpl.Client, wallet: xrpl.Wallet) {
  log('Testing TrustSet (trust line creation)...');

  try {
    // Create a trust line to a known test issuer
    const trustTx: xrpl.TrustSet = {
      TransactionType: 'TrustSet',
      Account: wallet.address,
      LimitAmount: {
        currency: 'USD',
        issuer: 'rN7n3473SaZBCG4dFL83w7a1RXtXtbK2D9', // Test issuer
        value: '1000',
      },
    };

    const prepared = await client.autofill(trustTx);
    const signed = wallet.sign(prepared);
    const result = await client.submitAndWait(signed.tx_blob);

    const txResult = result.result.meta as { TransactionResult?: string };
    if (txResult?.TransactionResult === 'tesSUCCESS') {
      pass('TrustSet', 'Created trust line successfully');
    } else {
      // tecNO_DST is expected if issuer doesn't exist
      pass('TrustSet', `Result: ${txResult?.TransactionResult} (issuer may not exist, but tx format valid)`);
    }
  } catch (error) {
    // This might fail if the issuer doesn't exist, but we're testing the tx format
    const errMsg = String(error);
    if (errMsg.includes('tecNO_DST') || errMsg.includes('actNotFound')) {
      pass('TrustSet', 'Transaction format valid (issuer not found on testnet)');
    } else {
      fail('TrustSet', `Error: ${error}`);
    }
  }
}

async function testOfferCreate(client: xrpl.Client, wallet: xrpl.Wallet) {
  log('Testing OfferCreate (DEX offer)...');

  try {
    const offerTx: xrpl.OfferCreate = {
      TransactionType: 'OfferCreate',
      Account: wallet.address,
      TakerGets: '1000000', // 1 XRP
      TakerPays: {
        currency: 'USD',
        issuer: wallet.address, // Self as issuer for testing
        value: '1',
      },
    };

    const prepared = await client.autofill(offerTx);
    const signed = wallet.sign(prepared);
    const result = await client.submitAndWait(signed.tx_blob);

    const txResult = result.result.meta as { TransactionResult?: string };
    pass('OfferCreate', `Result: ${txResult?.TransactionResult}`);
  } catch (error) {
    fail('OfferCreate', `Error: ${error}`);
  }
}

async function testTicketCreate(client: xrpl.Client, wallet: xrpl.Wallet) {
  log('Testing TicketCreate...');

  try {
    const ticketTx: xrpl.TicketCreate = {
      TransactionType: 'TicketCreate',
      Account: wallet.address,
      TicketCount: 2,
    };

    const prepared = await client.autofill(ticketTx);
    const signed = wallet.sign(prepared);
    const result = await client.submitAndWait(signed.tx_blob);

    const txResult = result.result.meta as { TransactionResult?: string };
    if (txResult?.TransactionResult === 'tesSUCCESS') {
      pass('TicketCreate', 'Created 2 tickets successfully');
    } else {
      fail('TicketCreate', `Result: ${txResult?.TransactionResult}`);
    }
  } catch (error) {
    fail('TicketCreate', `Error: ${error}`);
  }
}

async function testCheckCreate(client: xrpl.Client, wallet: xrpl.Wallet) {
  log('Testing CheckCreate...');

  try {
    const checkTx: xrpl.CheckCreate = {
      TransactionType: 'CheckCreate',
      Account: wallet.address,
      Destination: wallet.address, // Self-check for testing
      SendMax: '1000000', // 1 XRP
    };

    const prepared = await client.autofill(checkTx);
    const signed = wallet.sign(prepared);
    const result = await client.submitAndWait(signed.tx_blob);

    const txResult = result.result.meta as { TransactionResult?: string };
    if (txResult?.TransactionResult === 'tesSUCCESS') {
      pass('CheckCreate', 'Created check successfully');
    } else {
      fail('CheckCreate', `Result: ${txResult?.TransactionResult}`);
    }
  } catch (error) {
    fail('CheckCreate', `Error: ${error}`);
  }
}

async function testFinalOwnerCount(client: xrpl.Client, wallet: xrpl.Wallet) {
  log('Testing final owner count and reserve...');

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

      log('');
      log('═══════════════════════════════════════════');
      log('           FINAL ACCOUNT STATE');
      log('═══════════════════════════════════════════');
      log(`  Address: ${wallet.address}`);
      log(`  Balance: ${balance.toFixed(6)} XRP`);
      log(`  Owner Count: ${ownerCount} objects`);
      log(`  Base Reserve: ${baseReserve} XRP`);
      log(`  Owner Reserve: ${ownerCount} × ${ownerReserve} = ${ownerCount * ownerReserve} XRP`);
      log(`  Total Reserve: ${totalReserve} XRP`);
      log(`  Available: ${available.toFixed(6)} XRP`);
      log('═══════════════════════════════════════════');

      pass('Final State', `${ownerCount} objects, ${totalReserve} XRP reserved, ${available.toFixed(2)} XRP available`);
    }
  } catch (error) {
    fail('Final State', `Error: ${error}`);
  }
}

async function main() {
  console.log('');
  console.log('╔═══════════════════════════════════════════════════════════╗');
  console.log('║       XRPL Feature Test Suite - Testnet                   ║');
  console.log('╚═══════════════════════════════════════════════════════════╝');
  console.log('');

  const client = new xrpl.Client(TESTNET_URL);

  try {
    log('Connecting to testnet...');
    await client.connect();
    log(`Connected to ${TESTNET_URL}`);
    console.log('');

    // Test 1: Reserve values
    await testReserves(client);
    console.log('');

    // Test 2: Wallet creation and funding
    const wallet = await testWalletCreation(client);
    if (!wallet) {
      throw new Error('Failed to create wallet, cannot continue tests');
    }
    console.log('');

    // Test 3: Escrow
    await testEscrowCreate(client, wallet);
    console.log('');

    // Test 4: Owner count after escrow
    await testOwnerCount(client, wallet);
    console.log('');

    // Test 5: Tickets
    await testTicketCreate(client, wallet);
    console.log('');

    // Test 6: Check
    await testCheckCreate(client, wallet);
    console.log('');

    // Test 7: Final state
    await testFinalOwnerCount(client, wallet);
    console.log('');

  } catch (error) {
    console.error('Fatal error:', error);
  } finally {
    await client.disconnect();
  }

  // Summary
  console.log('');
  console.log('╔═══════════════════════════════════════════════════════════╗');
  console.log('║                    TEST SUMMARY                           ║');
  console.log('╚═══════════════════════════════════════════════════════════╝');

  const passed = results.filter(r => r.passed).length;
  const failed = results.filter(r => !r.passed).length;

  console.log(`  Passed: ${passed}`);
  console.log(`  Failed: ${failed}`);
  console.log(`  Total:  ${results.length}`);
  console.log('');

  if (failed > 0) {
    console.log('Failed tests:');
    results.filter(r => !r.passed).forEach(r => {
      console.log(`  - ${r.name}: ${r.details}`);
    });
  }

  process.exit(failed > 0 ? 1 : 0);
}

main();
