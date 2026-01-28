# ADR-007: Rate Limiting

**Status:** Accepted
**Date:** 2026-01-28
**Decision Makers:** Tech Lead, Security Specialist

---

## Context

The XRPL Agent Wallet MCP server must protect against denial-of-service attacks and resource abuse. Rate limiting controls how many requests can be processed within time windows.

Key concerns:
1. **DoS Prevention**: Prevent attackers from overwhelming the service
2. **Resource Protection**: Expensive operations (Argon2id) must be limited
3. **Fair Usage**: One misbehaving client shouldn't affect others
4. **Burst Allowance**: Legitimate agents may need occasional bursts
5. **UX Balance**: Limits shouldn't impede normal agent operations

The threat model identifies rate limit exhaustion (T-013) and KDF computational DoS (T-014) as significant risks.

## Decision

**We will implement a token bucket algorithm with sliding window tracking, using tiered limits based on operation sensitivity.**

### Rate Limit Tiers

| Tier | Operations | Requests/Minute | Burst | Window |
|------|------------|-----------------|-------|--------|
| **STANDARD** | Read operations (get_balance, list_wallets) | 100 | 10 | 60s |
| **STRICT** | Write operations (sign_transaction) | 20 | 2 | 60s |
| **CRITICAL** | Sensitive operations (import_wallet, export) | 5 | 0 | 300s |
| **AUTH** | Authentication attempts | 10 | 0 | 3600s (per IP) |

### Tool Classification

```typescript
const TOOL_RATE_LIMITS: Record<string, RateLimitTier> = {
  // STANDARD tier - read operations
  'list_wallets': 'STANDARD',
  'get_balance': 'STANDARD',
  'get_transaction_status': 'STANDARD',
  'get_policy': 'STANDARD',
  'check_policy': 'STANDARD',  // Dry-run policy check

  // STRICT tier - write operations
  'sign_transaction': 'STRICT',
  'set_regular_key': 'STRICT',
  'setup_multisign': 'STRICT',

  // CRITICAL tier - sensitive operations
  'create_wallet': 'CRITICAL',
  'import_wallet': 'CRITICAL',
  'export_wallet': 'CRITICAL',

  // AUTH tier - authentication
  'unlock_wallet': 'AUTH'
};
```

### Token Bucket Implementation

```typescript
interface TokenBucket {
  tokens: number;
  lastRefill: number;
  maxTokens: number;
  refillRate: number;  // tokens per second
}

interface RateLimitConfig {
  maxTokens: number;
  refillRate: number;
  windowMs: number;
}

const TIER_CONFIGS: Record<RateLimitTier, RateLimitConfig> = {
  STANDARD: {
    maxTokens: 100,
    refillRate: 100 / 60,  // 100 per minute = 1.67 per second
    windowMs: 60_000
  },
  STRICT: {
    maxTokens: 20,
    refillRate: 20 / 60,   // 20 per minute = 0.33 per second
    windowMs: 60_000
  },
  CRITICAL: {
    maxTokens: 5,
    refillRate: 5 / 300,   // 5 per 5 minutes = 0.017 per second
    windowMs: 300_000
  },
  AUTH: {
    maxTokens: 10,
    refillRate: 10 / 3600, // 10 per hour = 0.003 per second
    windowMs: 3_600_000
  }
};

class TokenBucketRateLimiter {
  private buckets: Map<string, TokenBucket> = new Map();

  constructor(private config: RateLimitConfig) {}

  tryConsume(identifier: string, tokens: number = 1): RateLimitResult {
    const bucket = this.getOrCreateBucket(identifier);
    this.refillBucket(bucket);

    if (bucket.tokens >= tokens) {
      bucket.tokens -= tokens;
      return {
        allowed: true,
        remaining: Math.floor(bucket.tokens),
        resetAt: this.calculateResetTime(bucket),
        limit: this.config.maxTokens
      };
    }

    return {
      allowed: false,
      remaining: 0,
      resetAt: this.calculateResetTime(bucket),
      retryAfter: this.calculateRetryAfter(bucket, tokens),
      limit: this.config.maxTokens
    };
  }

  private getOrCreateBucket(identifier: string): TokenBucket {
    let bucket = this.buckets.get(identifier);

    if (!bucket) {
      bucket = {
        tokens: this.config.maxTokens,
        lastRefill: Date.now(),
        maxTokens: this.config.maxTokens,
        refillRate: this.config.refillRate
      };
      this.buckets.set(identifier, bucket);
    }

    return bucket;
  }

  private refillBucket(bucket: TokenBucket): void {
    const now = Date.now();
    const elapsed = (now - bucket.lastRefill) / 1000;  // seconds
    const tokensToAdd = elapsed * bucket.refillRate;

    bucket.tokens = Math.min(bucket.maxTokens, bucket.tokens + tokensToAdd);
    bucket.lastRefill = now;
  }

  private calculateResetTime(bucket: TokenBucket): number {
    // Time until bucket is full
    const tokensNeeded = bucket.maxTokens - bucket.tokens;
    const secondsToFull = tokensNeeded / bucket.refillRate;
    return Date.now() + (secondsToFull * 1000);
  }

  private calculateRetryAfter(bucket: TokenBucket, tokensNeeded: number): number {
    // Time until enough tokens for this request
    const deficit = tokensNeeded - bucket.tokens;
    return Math.ceil(deficit / bucket.refillRate);
  }
}
```

### Sliding Window for Burst Control

```typescript
class SlidingWindowCounter {
  private windows: Map<string, { count: number; timestamp: number }[]> = new Map();

  constructor(
    private windowMs: number,
    private maxRequests: number
  ) {}

  check(identifier: string): boolean {
    const now = Date.now();
    const cutoff = now - this.windowMs;

    let entries = this.windows.get(identifier) || [];

    // Remove expired entries
    entries = entries.filter(e => e.timestamp > cutoff);

    // Count requests in current window
    const count = entries.reduce((sum, e) => sum + e.count, 0);

    return count < this.maxRequests;
  }

  record(identifier: string): void {
    const now = Date.now();
    const entries = this.windows.get(identifier) || [];
    entries.push({ count: 1, timestamp: now });
    this.windows.set(identifier, entries);
  }
}
```

### Combined Rate Limiter

```typescript
class CombinedRateLimiter {
  private tokenBuckets: Map<RateLimitTier, TokenBucketRateLimiter> = new Map();
  private slidingWindows: Map<RateLimitTier, SlidingWindowCounter> = new Map();

  constructor() {
    for (const [tier, config] of Object.entries(TIER_CONFIGS)) {
      this.tokenBuckets.set(
        tier as RateLimitTier,
        new TokenBucketRateLimiter(config)
      );
      this.slidingWindows.set(
        tier as RateLimitTier,
        new SlidingWindowCounter(config.windowMs, config.maxTokens)
      );
    }
  }

  async checkLimit(
    identifier: string,
    toolName: string,
    correlationId: string
  ): Promise<RateLimitResult> {
    const tier = TOOL_RATE_LIMITS[toolName] || 'STANDARD';
    const tokenBucket = this.tokenBuckets.get(tier)!;
    const slidingWindow = this.slidingWindows.get(tier)!;

    // Check sliding window first (prevents burst at window boundaries)
    if (!slidingWindow.check(identifier)) {
      await this.logRateLimitExceeded(identifier, toolName, tier, correlationId);
      return {
        allowed: false,
        remaining: 0,
        resetAt: Date.now() + TIER_CONFIGS[tier].windowMs,
        retryAfter: Math.ceil(TIER_CONFIGS[tier].windowMs / 1000),
        limit: TIER_CONFIGS[tier].maxTokens
      };
    }

    // Check token bucket
    const result = tokenBucket.tryConsume(identifier);

    if (result.allowed) {
      slidingWindow.record(identifier);
    } else {
      await this.logRateLimitExceeded(identifier, toolName, tier, correlationId);
    }

    return result;
  }

  private async logRateLimitExceeded(
    identifier: string,
    toolName: string,
    tier: RateLimitTier,
    correlationId: string
  ): Promise<void> {
    await auditLog.log({
      eventType: 'SECURITY_RATE_LIMIT',
      correlationId,
      operation: {
        name: toolName,
        parameters: { tier, identifier: hashIdentifier(identifier) },
        result: 'denied',
        errorCode: 'RATE_LIMIT_EXCEEDED'
      }
    });
  }
}
```

### Client Identification

```typescript
function getClientIdentifier(request: MCPRequest): string {
  // Priority: session token > API key > connection ID
  if (request.sessionToken) {
    return `session:${hashToken(request.sessionToken)}`;
  }

  if (request.apiKey) {
    return `apikey:${hashToken(request.apiKey)}`;
  }

  // Fallback to connection-based identification
  return `conn:${request.connectionId}`;
}

// For AUTH tier, also track by "account" (wallet address being unlocked)
function getAuthIdentifier(request: MCPRequest, walletAddress: string): string {
  return `auth:${walletAddress}`;
}
```

## Consequences

### Positive

- **Burst Tolerance**: Token bucket allows legitimate bursts within limits
- **Smooth Limiting**: Sliding window prevents gaming at boundaries
- **Tier Flexibility**: Different limits for different risk levels
- **Client Isolation**: One client's abuse doesn't affect others
- **Clear Feedback**: Remaining tokens and reset times in responses
- **DoS Mitigation**: Expensive operations strictly limited

### Negative

- **Memory Usage**: Per-client buckets consume memory (mitigated by cleanup)
- **Complexity**: Two algorithms (token bucket + sliding window) to understand
- **Tuning Required**: Limits may need adjustment based on real usage
- **Clock Sensitivity**: Accurate timing required for correct behavior

### Neutral

- Limits are configurable but require restart to change
- Distributed deployments would need shared state (future consideration)
- Rate limit state lost on restart (acceptable for Phase 1)

## Alternatives Considered

| Option | Pros | Cons | Why Not Chosen |
|--------|------|------|----------------|
| **Fixed Window** | Simple | Allows 2x burst at window boundary | Gaming vulnerability |
| **Leaky Bucket** | Smooth output rate | No burst tolerance | Poor UX for legitimate bursts |
| **Token Bucket Only** | Burst support | Can game window boundaries | Need sliding window complement |
| **Sliding Window Only** | No boundary gaming | No burst support | Need token bucket for bursts |
| **External Service (Redis)** | Distributed | Added dependency | Phase 1 is single-instance |

## Implementation Notes

### Response Headers

```typescript
function addRateLimitHeaders(
  response: MCPResponse,
  result: RateLimitResult
): void {
  response.headers = {
    ...response.headers,
    'X-RateLimit-Limit': result.limit.toString(),
    'X-RateLimit-Remaining': result.remaining.toString(),
    'X-RateLimit-Reset': Math.ceil(result.resetAt / 1000).toString()
  };

  if (!result.allowed) {
    response.headers['Retry-After'] = result.retryAfter.toString();
  }
}
```

### Error Response

```typescript
// 429 Too Many Requests
{
  "error": {
    "code": "RATE_LIMIT_EXCEEDED",
    "message": "Too many requests. Please retry after the specified time.",
    "correlationId": "123e4567-e89b-12d3-a456-426614174000",
    "retryAfter": 30,
    "limit": 20,
    "window": "60s"
  }
}
```

### Cleanup Stale Buckets

```typescript
class RateLimiterWithCleanup extends CombinedRateLimiter {
  private cleanupInterval: NodeJS.Timeout;

  constructor() {
    super();
    // Clean up stale buckets every 5 minutes
    this.cleanupInterval = setInterval(() => this.cleanup(), 5 * 60 * 1000);
  }

  private cleanup(): void {
    const now = Date.now();

    for (const [tier, bucket] of this.tokenBuckets) {
      const config = TIER_CONFIGS[tier];
      // Remove buckets not accessed in 2x window time
      const cutoff = now - (config.windowMs * 2);

      for (const [identifier, state] of bucket.buckets) {
        if (state.lastRefill < cutoff) {
          bucket.buckets.delete(identifier);
        }
      }
    }
  }

  destroy(): void {
    clearInterval(this.cleanupInterval);
  }
}
```

### Authentication Rate Limiting (Special Case)

```typescript
class AuthRateLimiter {
  private perIpLimiter: TokenBucketRateLimiter;
  private perAccountLimiter: TokenBucketRateLimiter;

  constructor() {
    // 10 attempts per IP per hour
    this.perIpLimiter = new TokenBucketRateLimiter({
      maxTokens: 10,
      refillRate: 10 / 3600,
      windowMs: 3_600_000
    });

    // 5 attempts per account per 15 minutes
    this.perAccountLimiter = new TokenBucketRateLimiter({
      maxTokens: 5,
      refillRate: 5 / 900,
      windowMs: 900_000
    });
  }

  async checkAuthLimit(
    ipAddress: string,
    walletAddress: string,
    correlationId: string
  ): Promise<RateLimitResult> {
    // Check both limits - both must pass
    const ipResult = this.perIpLimiter.tryConsume(`ip:${ipAddress}`);
    const accountResult = this.perAccountLimiter.tryConsume(`account:${walletAddress}`);

    if (!ipResult.allowed || !accountResult.allowed) {
      await auditLog.log({
        eventType: 'SECURITY_RATE_LIMIT',
        correlationId,
        operation: {
          name: 'unlock_wallet',
          parameters: {
            ipLimited: !ipResult.allowed,
            accountLimited: !accountResult.allowed
          },
          result: 'denied',
          errorCode: 'AUTH_RATE_LIMIT_EXCEEDED'
        }
      });

      // Return the more restrictive result
      return ipResult.allowed ? accountResult : ipResult;
    }

    return { ...ipResult, allowed: true };
  }
}
```

## Security Considerations

### Rate Limit Bypass Prevention

- Identifier hashing prevents enumeration of other clients
- Multiple identification methods prevent spoofing
- Sliding window prevents boundary gaming
- No rate limit information in error messages (just retry-after)

### Compliance Mapping

| Requirement | Implementation |
|-------------|----------------|
| RATE-001 | Tiered configuration |
| RATE-002 | Sliding window algorithm |
| RATE-003 | Token bucket for bursts |
| RATE-004 | X-RateLimit-* headers |
| RATE-005 | Per-client tracking |
| RATE-006 | AuthRateLimiter class |

## References

- [Token Bucket Algorithm](https://en.wikipedia.org/wiki/Token_bucket)
- [Sliding Window Rate Limiting](https://blog.cloudflare.com/counting-things-a-lot-of-different-things/)
- [Zuplo Rate Limiting Best Practices](https://zuplo.com/learning-center/10-best-practices-for-api-rate-limiting-in-2025)
- Security Requirements: RATE-001 through RATE-006

## Related ADRs

- [ADR-002: Key Derivation](ADR-002-key-derivation.md) - Argon2id requires AUTH rate limiting
- [ADR-005: Audit Logging](ADR-005-audit-logging.md) - Rate limit events logged
- [ADR-006: Input Validation](ADR-006-input-validation.md) - Runs before rate limiting

---

**Document History**

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0.0 | 2026-01-28 | Tech Lead | Initial ADR |
