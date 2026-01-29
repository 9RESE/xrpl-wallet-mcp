/**
 * Limit Tracker Implementation
 *
 * Token bucket rate limiting with rolling window counters for
 * transaction count, volume, and destination tracking.
 *
 * @module policy/limits
 * @version 1.0.0
 */

import type {
  LimitConfig,
  LimitState,
  LimitCheckResult,
  PolicyContext,
} from './types.js';

// ============================================================================
// LIMIT TRACKER
// ============================================================================

/**
 * Options for LimitTracker construction.
 */
export interface LimitTrackerOptions {
  /** Limit configuration */
  config: LimitConfig;
  /** Path for persisting state (optional) */
  persistencePath?: string | undefined;
  /** Custom clock for testing */
  clock?: (() => Date) | undefined;
}

/**
 * Tracks transaction limits using rolling windows and daily resets.
 *
 * Features:
 * - Daily transaction count limits (resets at configured UTC hour)
 * - Hourly transaction count limits (sliding 1-hour window)
 * - Daily XRP volume limits
 * - Unique destination tracking per day
 * - Optional cooldown after high-value transactions
 * - State persistence across restarts (optional)
 */
export class LimitTracker {
  private state: LimitState;
  private readonly config: LimitConfig;
  private readonly persistencePath: string | undefined;
  private readonly clock: () => Date;
  private resetInterval: ReturnType<typeof setInterval> | undefined;

  constructor(options: LimitTrackerOptions) {
    this.config = options.config;
    this.persistencePath = options.persistencePath;
    this.clock = options.clock ?? (() => new Date());

    // Initialize fresh state
    this.state = this.createFreshState();

    // Schedule periodic reset checks (every minute)
    this.schedulePeriodicCheck();
  }

  /**
   * Create fresh limit state.
   */
  private createFreshState(): LimitState {
    const now = this.clock();
    return {
      daily: {
        date: this.getDateString(now),
        transactionCount: 0,
        totalVolumeXrp: 0,
        uniqueDestinations: new Set(),
        lastTransactionTime: null,
      },
      hourly: {
        transactions: [],
      },
      cooldown: {
        active: false,
        reason: null,
        expiresAt: null,
        triggeredBy: null,
      },
    };
  }

  /**
   * Check if a transaction would exceed any limits.
   * Does NOT record the transaction - call recordTransaction after successful signing.
   */
  checkLimits(context: PolicyContext): LimitCheckResult {
    const now = this.clock();

    // Ensure state is current
    this.maybeResetDaily(now);
    this.pruneHourlyWindow(now);

    // Check cooldown
    if (this.state.cooldown.active) {
      if (this.state.cooldown.expiresAt && now < this.state.cooldown.expiresAt) {
        return {
          exceeded: true,
          reason: `Cooldown active: ${this.state.cooldown.reason}`,
          limitType: 'cooldown',
          currentValue: 0,
          limitValue: 0,
          expiresAt: this.state.cooldown.expiresAt,
        };
      } else {
        this.clearCooldown();
      }
    }

    // Check per-transaction amount limit
    const txAmountXrp = context.transaction.amount_xrp ?? 0;
    if (
      this.config.maxAmountPerTxXrp !== undefined &&
      txAmountXrp > this.config.maxAmountPerTxXrp
    ) {
      return {
        exceeded: true,
        reason: `Transaction amount ${txAmountXrp} XRP exceeds per-tx limit of ${this.config.maxAmountPerTxXrp} XRP`,
        limitType: 'per_tx_amount',
        currentValue: txAmountXrp,
        limitValue: this.config.maxAmountPerTxXrp,
      };
    }

    // Check daily transaction count
    if (this.state.daily.transactionCount >= this.config.maxTransactionsPerDay) {
      return {
        exceeded: true,
        reason: `Daily transaction count limit (${this.config.maxTransactionsPerDay}) exceeded`,
        limitType: 'daily_count',
        currentValue: this.state.daily.transactionCount,
        limitValue: this.config.maxTransactionsPerDay,
      };
    }

    // Check hourly transaction count
    const hourlyCount = this.state.hourly.transactions.length;
    if (hourlyCount >= this.config.maxTransactionsPerHour) {
      return {
        exceeded: true,
        reason: `Hourly transaction count limit (${this.config.maxTransactionsPerHour}) exceeded`,
        limitType: 'hourly_count',
        currentValue: hourlyCount,
        limitValue: this.config.maxTransactionsPerHour,
      };
    }

    // Check daily volume
    const projectedVolume = this.state.daily.totalVolumeXrp + txAmountXrp;
    if (projectedVolume > this.config.maxTotalVolumeXrpPerDay) {
      return {
        exceeded: true,
        reason: `Daily XRP volume limit (${this.config.maxTotalVolumeXrpPerDay} XRP) would be exceeded`,
        limitType: 'daily_volume',
        currentValue: this.state.daily.totalVolumeXrp,
        limitValue: this.config.maxTotalVolumeXrpPerDay,
        requestedAmount: txAmountXrp,
      };
    }

    // Check unique destinations limit
    const destination = context.transaction.destination;
    if (
      this.config.maxUniqueDestinationsPerDay !== undefined &&
      destination &&
      !this.state.daily.uniqueDestinations.has(destination) &&
      this.state.daily.uniqueDestinations.size >= this.config.maxUniqueDestinationsPerDay
    ) {
      return {
        exceeded: true,
        reason: `Daily unique destination limit (${this.config.maxUniqueDestinationsPerDay}) exceeded`,
        limitType: 'unique_destinations',
        currentValue: this.state.daily.uniqueDestinations.size,
        limitValue: this.config.maxUniqueDestinationsPerDay,
      };
    }

    return { exceeded: false };
  }

  /**
   * Record a successfully signed transaction.
   * Call this AFTER signing succeeds, not before.
   */
  recordTransaction(context: PolicyContext): void {
    const now = this.clock();

    // Ensure state is current
    this.maybeResetDaily(now);
    this.pruneHourlyWindow(now);

    const txAmountXrp = context.transaction.amount_xrp ?? 0;
    const destination = context.transaction.destination;

    // Update daily stats
    this.state.daily.transactionCount++;
    this.state.daily.totalVolumeXrp += txAmountXrp;
    this.state.daily.lastTransactionTime = now;
    if (destination) {
      this.state.daily.uniqueDestinations.add(destination);
    }

    // Update hourly window
    this.state.hourly.transactions.push({
      timestamp: now,
      amountXrp: txAmountXrp,
      destination: destination ?? '',
    });

    // Check if cooldown should be triggered
    const cooldownConfig = this.config.cooldownAfterHighValue;
    if (
      cooldownConfig?.enabled &&
      txAmountXrp >= cooldownConfig.thresholdXrp
    ) {
      this.activateCooldown(
        `High-value transaction (${txAmountXrp} XRP)`,
        cooldownConfig.cooldownSeconds,
        context.transaction.type
      );
    }
  }

  /**
   * Check if daily reset should happen.
   */
  private maybeResetDaily(now: Date): void {
    const currentDate = this.getDateString(now);
    const currentHour = now.getUTCHours();

    // Check if we've crossed the reset boundary
    const shouldReset =
      this.state.daily.date !== currentDate ||
      (this.state.daily.date === currentDate &&
        currentHour >= this.config.dailyResetHour &&
        this.state.daily.lastTransactionTime &&
        this.state.daily.lastTransactionTime.getUTCHours() < this.config.dailyResetHour);

    if (shouldReset) {
      this.state.daily = {
        date: currentDate,
        transactionCount: 0,
        totalVolumeXrp: 0,
        uniqueDestinations: new Set(),
        lastTransactionTime: null,
      };
    }
  }

  /**
   * Remove transactions older than 1 hour from sliding window.
   */
  private pruneHourlyWindow(now: Date): void {
    const oneHourAgo = new Date(now.getTime() - 60 * 60 * 1000);

    this.state.hourly.transactions = this.state.hourly.transactions.filter(
      (tx) => tx.timestamp > oneHourAgo
    );
  }

  /**
   * Activate cooldown period.
   */
  private activateCooldown(
    reason: string,
    durationSeconds: number,
    triggeredBy: string
  ): void {
    const now = this.clock();
    this.state.cooldown = {
      active: true,
      reason,
      expiresAt: new Date(now.getTime() + durationSeconds * 1000),
      triggeredBy,
    };
  }

  /**
   * Clear active cooldown.
   */
  private clearCooldown(): void {
    this.state.cooldown = {
      active: false,
      reason: null,
      expiresAt: null,
      triggeredBy: null,
    };
  }

  /**
   * Schedule periodic check for daily reset.
   */
  private schedulePeriodicCheck(): void {
    // Check every minute
    this.resetInterval = setInterval(() => {
      this.maybeResetDaily(this.clock());
    }, 60 * 1000);
  }

  /**
   * Stop periodic checks (for cleanup).
   */
  dispose(): void {
    if (this.resetInterval) {
      clearInterval(this.resetInterval);
      this.resetInterval = undefined;
    }
  }

  // ============================================================================
  // GETTERS FOR RULE EVALUATION
  // ============================================================================

  /**
   * Get current daily XRP volume.
   */
  getDailyVolumeXrp(): number {
    this.maybeResetDaily(this.clock());
    return this.state.daily.totalVolumeXrp;
  }

  /**
   * Get transactions in the last hour.
   */
  getHourlyCount(): number {
    const now = this.clock();
    this.pruneHourlyWindow(now);
    return this.state.hourly.transactions.length;
  }

  /**
   * Get daily transaction count.
   */
  getDailyCount(): number {
    this.maybeResetDaily(this.clock());
    return this.state.daily.transactionCount;
  }

  /**
   * Get unique destination count for today.
   */
  getUniqueDestinationCount(): number {
    this.maybeResetDaily(this.clock());
    return this.state.daily.uniqueDestinations.size;
  }

  /**
   * Check if a destination has been used before today.
   */
  isDestinationKnown(destination: string): boolean {
    this.maybeResetDaily(this.clock());
    return this.state.daily.uniqueDestinations.has(destination);
  }

  /**
   * Get complete limit state (copy for safety).
   */
  getState(): LimitState {
    const now = this.clock();
    this.maybeResetDaily(now);
    this.pruneHourlyWindow(now);

    return {
      daily: {
        ...this.state.daily,
        uniqueDestinations: new Set(this.state.daily.uniqueDestinations),
      },
      hourly: {
        transactions: [...this.state.hourly.transactions],
      },
      cooldown: { ...this.state.cooldown },
    };
  }

  /**
   * Get remaining limits for current period.
   */
  getRemainingLimits(): {
    dailyTxRemaining: number;
    hourlyTxRemaining: number;
    dailyVolumeRemainingXrp: number;
    uniqueDestinationsRemaining: number;
  } {
    const now = this.clock();
    this.maybeResetDaily(now);
    this.pruneHourlyWindow(now);

    return {
      dailyTxRemaining: Math.max(
        0,
        this.config.maxTransactionsPerDay - this.state.daily.transactionCount
      ),
      hourlyTxRemaining: Math.max(
        0,
        this.config.maxTransactionsPerHour - this.state.hourly.transactions.length
      ),
      dailyVolumeRemainingXrp: Math.max(
        0,
        this.config.maxTotalVolumeXrpPerDay - this.state.daily.totalVolumeXrp
      ),
      uniqueDestinationsRemaining: Math.max(
        0,
        (this.config.maxUniqueDestinationsPerDay ?? Infinity) -
          this.state.daily.uniqueDestinations.size
      ),
    };
  }

  /**
   * Reset all limits. Requires confirmation string for safety.
   */
  reset(confirmation: string): void {
    if (confirmation !== 'CONFIRM_LIMIT_RESET') {
      throw new Error('Invalid confirmation string for limit reset');
    }
    this.state = this.createFreshState();
  }

  /**
   * Get date string in YYYY-MM-DD format.
   */
  private getDateString(date: Date): string {
    // ISO date format is always YYYY-MM-DDTHH:mm:ss.sssZ, so split always produces [date, time]
    return date.toISOString().split('T')[0]!;
  }
}

// ============================================================================
// FACTORY FUNCTION
// ============================================================================

/**
 * Create a LimitTracker from policy limits configuration.
 */
export function createLimitTracker(
  limits: {
    max_tx_per_hour: number;
    max_tx_per_day: number;
    max_daily_volume_drops: string;
    max_amount_per_tx_drops: string;
  },
  options?: {
    dailyResetHour?: number | undefined;
    maxUniqueDestinationsPerDay?: number | undefined;
    cooldownAfterHighValue?: {
      enabled: boolean;
      thresholdXrp: number;
      cooldownSeconds: number;
    } | undefined;
    clock?: (() => Date) | undefined;
  }
): LimitTracker {
  // Convert drops to XRP
  const dropsToXrp = (drops: string): number => {
    return Number(BigInt(drops)) / 1_000_000;
  };

  const config: LimitConfig = {
    dailyResetHour: options?.dailyResetHour ?? 0,
    maxTransactionsPerHour: limits.max_tx_per_hour,
    maxTransactionsPerDay: limits.max_tx_per_day,
    maxTotalVolumeXrpPerDay: dropsToXrp(limits.max_daily_volume_drops),
    maxAmountPerTxXrp: dropsToXrp(limits.max_amount_per_tx_drops),
    maxUniqueDestinationsPerDay: options?.maxUniqueDestinationsPerDay,
    cooldownAfterHighValue: options?.cooldownAfterHighValue,
  };

  const trackerOptions: LimitTrackerOptions = {
    config,
  };
  if (options?.clock) {
    trackerOptions.clock = options.clock;
  }

  return new LimitTracker(trackerOptions);
}
