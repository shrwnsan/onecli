import { describe, it, expect, beforeEach, vi } from "vitest";
import {
  checkRateLimit,
  getRemainingTokens,
  getRateLimitKey,
  resetBucket,
  resetAllBuckets,
} from "@/lib/rate-limit";

describe("checkRateLimit", () => {
  beforeEach(() => {
    resetAllBuckets();
  });

  it("allows requests within capacity", () => {
    const opts = { capacity: 5, refillRate: 1 };
    for (let i = 0; i < 5; i++) {
      expect(checkRateLimit("a", opts)).toBe(true);
    }
    // 6th should be denied
    expect(checkRateLimit("a", opts)).toBe(false);
  });

  it("isolates buckets by key", () => {
    const opts = { capacity: 2, refillRate: 1 };
    expect(checkRateLimit("a", opts)).toBe(true);
    expect(checkRateLimit("a", opts)).toBe(true);
    expect(checkRateLimit("a", opts)).toBe(false);
    // Different key should have its own bucket
    expect(checkRateLimit("b", opts)).toBe(true);
  });

  it("refills tokens over time", () => {
    const opts = { capacity: 3, refillRate: 100 }; // 100 tokens/sec
    // Exhaust the bucket
    checkRateLimit("c", opts);
    checkRateLimit("c", opts);
    checkRateLimit("c", opts);
    expect(checkRateLimit("c", opts)).toBe(false);

    // Mock Date.now to simulate time passing
    const now = Date.now();
    vi.useFakeTimers({ now });
    vi.advanceTimersByTime(50); // 50ms → should refill 5 tokens
    expect(checkRateLimit("c", opts)).toBe(true);
    vi.useRealTimers();
  });

  it("uses default options when none provided", () => {
    // Default capacity is 100 — should allow 100 requests
    for (let i = 0; i < 100; i++) {
      expect(checkRateLimit("d")).toBe(true);
    }
    expect(checkRateLimit("d")).toBe(false);
  });

  it("never exceeds capacity", () => {
    const opts = { capacity: 5, refillRate: 1000 };
    checkRateLimit("e", opts); // consume 1
    vi.useFakeTimers({ now: Date.now() });
    vi.advanceTimersByTime(10_000); // would refill 10000 tokens
    // getRemainingTokens should be capped at capacity
    expect(getRemainingTokens("e", opts)).toBe(5); // refilled to capacity
    vi.useRealTimers();
  });
});

describe("getRemainingTokens", () => {
  beforeEach(() => {
    resetAllBuckets();
  });

  it("returns capacity for unknown key", () => {
    expect(getRemainingTokens("new-key", { capacity: 50, refillRate: 5 })).toBe(
      50,
    );
  });

  it("returns remaining after consumption", () => {
    const opts = { capacity: 10, refillRate: 1 };
    checkRateLimit("f", opts);
    checkRateLimit("f", opts);
    expect(getRemainingTokens("f", opts)).toBe(8);
  });
});

describe("getRateLimitKey", () => {
  it("extracts from X-Forwarded-For", () => {
    const req = new Request("http://localhost", {
      headers: { "x-forwarded-for": "1.2.3.4, 10.0.0.1" },
    });
    expect(getRateLimitKey(req)).toBe("1.2.3.4");
  });

  it("falls back to X-Real-IP", () => {
    const req = new Request("http://localhost", {
      headers: { "x-real-ip": "5.6.7.8" },
    });
    expect(getRateLimitKey(req)).toBe("5.6.7.8");
  });

  it("returns 'unknown' when no headers present", () => {
    const req = new Request("http://localhost");
    expect(getRateLimitKey(req)).toBe("unknown");
  });
});

describe("resetBucket / resetAllBuckets", () => {
  it("resetBucket removes a specific bucket", () => {
    checkRateLimit("g", { capacity: 1, refillRate: 1 });
    expect(checkRateLimit("g", { capacity: 1, refillRate: 1 })).toBe(false);
    resetBucket("g");
    expect(checkRateLimit("g", { capacity: 1, refillRate: 1 })).toBe(true);
  });

  it("resetAllBuckets clears everything", () => {
    checkRateLimit("h", { capacity: 1, refillRate: 1 });
    checkRateLimit("i", { capacity: 1, refillRate: 1 });
    resetAllBuckets();
    expect(checkRateLimit("h", { capacity: 1, refillRate: 1 })).toBe(true);
    expect(checkRateLimit("i", { capacity: 1, refillRate: 1 })).toBe(true);
  });
});
