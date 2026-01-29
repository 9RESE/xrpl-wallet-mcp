/**
 * Sequence Tracker for XRPL Transactions
 *
 * Tracks locally-signed sequences to prevent tefPAST_SEQ errors in
 * multi-transaction workflows where ledger queries may return stale data.
 *
 * The problem: After signing TX with sequence N, the ledger's account_info
 * may still return sequence N until the TX is validated. If we sign TX B
 * immediately after, it would also get sequence N and fail.
 *
 * The solution: Track sequences we've signed locally and use
 * MAX(ledger_sequence, last_signed_sequence + 1) for the next TX.
 *
 * @module xrpl/sequence-tracker
 * @version 1.0.0
 * @since 2026-01-29 - ADR-013 race condition fix
 */

/**
 * Entry for tracking a signed sequence with timestamp for expiration.
 */
interface SequenceEntry {
  /** The sequence number that was signed */
  sequence: number;
  /** When this entry was recorded (for expiration) */
  timestamp: number;
}

/**
 * Tracks signed transaction sequences per address to prevent race conditions.
 *
 * When multiple transactions are signed in quick succession, the XRPL
 * ledger query may return stale sequence numbers. This tracker ensures
 * we always use the correct next sequence by remembering what we've signed.
 *
 * Entries expire after a configurable TTL (default: 60 seconds) to handle
 * cases where transactions fail or are never submitted.
 */
export class SequenceTracker {
  /** Map of address -> last signed sequence entry */
  private sequences: Map<string, SequenceEntry> = new Map();

  /** TTL for sequence entries in milliseconds (default: 60 seconds) */
  private readonly ttlMs: number;

  /**
   * Create a new SequenceTracker.
   *
   * @param ttlMs - Time-to-live for entries in milliseconds (default: 60000)
   */
  constructor(ttlMs: number = 60000) {
    this.ttlMs = ttlMs;
  }

  /**
   * Get the next sequence number to use for an address.
   *
   * Returns MAX(ledgerSequence, lastSignedSequence + 1) to handle
   * the race condition where ledger hasn't caught up yet.
   *
   * @param address - The XRPL account address
   * @param ledgerSequence - Current sequence from ledger query
   * @returns The sequence number to use for signing
   */
  getNextSequence(address: string, ledgerSequence: number): number {
    const entry = this.sequences.get(address);
    const now = Date.now();

    // No tracked entry or entry expired - use ledger sequence
    if (!entry || (now - entry.timestamp) > this.ttlMs) {
      return ledgerSequence;
    }

    // Use MAX of ledger sequence and (tracked sequence + 1)
    // This ensures we don't reuse a sequence we've already signed with
    const trackedNext = entry.sequence + 1;
    return Math.max(ledgerSequence, trackedNext);
  }

  /**
   * Record that a transaction was signed with a specific sequence.
   *
   * Call this AFTER successful signing to track the sequence used.
   * Only updates if the new sequence is greater than the current tracked value.
   *
   * @param address - The XRPL account address
   * @param sequence - The sequence number that was signed
   */
  recordSignedSequence(address: string, sequence: number): void {
    const existing = this.sequences.get(address);

    // Only update if new sequence is greater than existing
    // This prevents issues if calls come out of order
    if (!existing || sequence > existing.sequence) {
      this.sequences.set(address, {
        sequence,
        timestamp: Date.now(),
      });
    }
  }

  /**
   * Clear the tracked sequence for an address.
   *
   * Useful when a transaction is known to have failed or been rejected,
   * allowing the sequence to be reused.
   *
   * @param address - The XRPL account address
   */
  clearSequence(address: string): void {
    this.sequences.delete(address);
  }

  /**
   * Clear all expired entries from the tracker.
   *
   * Called periodically to prevent memory growth. Entries older than
   * TTL are removed.
   */
  cleanup(): void {
    const now = Date.now();
    for (const [address, entry] of this.sequences.entries()) {
      if ((now - entry.timestamp) > this.ttlMs) {
        this.sequences.delete(address);
      }
    }
  }

  /**
   * Get debug info about tracked sequences.
   *
   * @returns Map of address to sequence info (for debugging/testing)
   */
  getDebugInfo(): Map<string, { sequence: number; ageMs: number }> {
    const now = Date.now();
    const info = new Map<string, { sequence: number; ageMs: number }>();

    for (const [address, entry] of this.sequences.entries()) {
      info.set(address, {
        sequence: entry.sequence,
        ageMs: now - entry.timestamp,
      });
    }

    return info;
  }
}

/**
 * Singleton instance of the sequence tracker.
 * Shared across all signing operations for the server lifetime.
 */
let globalTracker: SequenceTracker | null = null;

/**
 * Get or create the global sequence tracker instance.
 *
 * @param ttlMs - TTL for entries (only used on first call)
 * @returns The global SequenceTracker instance
 */
export function getSequenceTracker(ttlMs?: number): SequenceTracker {
  if (!globalTracker) {
    globalTracker = new SequenceTracker(ttlMs);
  }
  return globalTracker;
}

/**
 * Reset the global sequence tracker (for testing).
 */
export function resetSequenceTracker(): void {
  globalTracker = null;
}
