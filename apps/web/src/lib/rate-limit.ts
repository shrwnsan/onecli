/**
 * In-memory sliding window rate limiter.
 *
 * Tracks requests per key (e.g. IP address) within a rolling time window.
 * Single-process only — adequate for a single-container deployment.
 *
 * Tokens are replenished at a constant rate. Each request consumes one token.
 * When the bucket is empty, the request is rejected with a 429 response.
 */

interface Bucket {
  tokens: number;
  lastRefill: number;
}

type LimitKey = string;

const buckets = new Map<LimitKey, Bucket>();

interface RateLimitOptions {
  /** Maximum tokens in the bucket (burst capacity). Default: 100 */
  capacity?: number;
  /** Tokens replenished per second. Default: 10 */
  refillRate?: number;
}

const DEFAULT_CAPACITY = 100;
const DEFAULT_REFILL_RATE = 10;

/**
 * Check whether a request is allowed under the rate limit.
 * Returns `true` if allowed, `false` if rate-limited.
 *
 * This function is side-effectful — it updates the bucket state.
 */
export const checkRateLimit = (
  key: string,
  options: RateLimitOptions = {},
): boolean => {
  const capacity = options.capacity ?? DEFAULT_CAPACITY;
  const refillRate = options.refillRate ?? DEFAULT_REFILL_RATE;

  const now = Date.now();
  let bucket = buckets.get(key);

  if (!bucket) {
    bucket = { tokens: capacity - 1, lastRefill: now };
    buckets.set(key, bucket);
    return true;
  }

  // Refill tokens based on elapsed time
  const elapsed = (now - bucket.lastRefill) / 1000;
  bucket.tokens = Math.min(capacity, bucket.tokens + elapsed * refillRate);
  bucket.lastRefill = now;

  if (bucket.tokens >= 1) {
    bucket.tokens -= 1;
    return true;
  }

  return false;
};

/**
 * Get the number of remaining tokens for a key (useful for rate-limit headers).
 */
export const getRemainingTokens = (
  key: string,
  options: RateLimitOptions = {},
): number => {
  const capacity = options.capacity ?? DEFAULT_CAPACITY;
  const refillRate = options.refillRate ?? DEFAULT_REFILL_RATE;

  const bucket = buckets.get(key);
  if (!bucket) return capacity;

  const now = Date.now();
  const elapsed = (now - bucket.lastRefill) / 1000;
  return Math.min(capacity, Math.floor(bucket.tokens + elapsed * refillRate));
};

/**
 * Extract a rate-limit key from a request.
 * Uses the client IP from X-Forwarded-For or falls back to a default.
 */
export const getRateLimitKey = (request: Request): string => {
  const forwarded = request.headers.get("x-forwarded-for");
  if (forwarded) {
    // Use the first IP in the chain (original client)
    return forwarded.split(",")[0]!.trim();
  }

  const realIp = request.headers.get("x-real-ip");
  if (realIp) return realIp;

  // Fallback — in dev/single-container this means all requests share a bucket
  return "unknown";
};

/**
 * Reset a rate-limit bucket (useful for testing).
 */
export const resetBucket = (key: string): void => {
  buckets.delete(key);
};

/**
 * Reset all buckets (useful for testing).
 */
export const resetAllBuckets = (): void => {
  buckets.clear();
};
