import { describe, it, expect, vi, beforeEach } from "vitest";

vi.mock("@/lib/env", () => ({
  IS_CLOUD: false,
  GOOGLE_CLIENT_ID: "",
  NEXTAUTH_SECRET: "",
  SECRET_ENCRYPTION_KEY: "test-key",
}));

import { proxy } from "@/proxy";
import { resetAllBuckets } from "@/lib/rate-limit";

const mockApiRequest = (pathname: string, ip = "1.2.3.4") =>
  ({
    nextUrl: { pathname },
    headers: new Headers({ "x-forwarded-for": ip }),
    url: `http://localhost:10254${pathname}`,
  }) as unknown as import("next/server").NextRequest;

const mockPageRequest = (pathname: string) =>
  ({
    nextUrl: { pathname },
    headers: new Headers(),
    url: `http://localhost:10254${pathname}`,
  }) as unknown as import("next/server").NextRequest;

describe("proxy — rate limiting on API routes", () => {
  beforeEach(() => {
    resetAllBuckets();
  });

  it("allows API requests within rate limit", () => {
    const response = proxy(mockApiRequest("/api/agents"));
    expect(response.status).toBe(200);
    expect(response.headers.get("x-ratelimit-remaining")).toBeTruthy();
  });

  it("returns 429 when rate limit exceeded", () => {
    // Default API limit is 100 burst — exhaust it
    for (let i = 0; i < 100; i++) {
      proxy(mockApiRequest("/api/agents"));
    }
    const response = proxy(mockApiRequest("/api/agents"));
    expect(response.status).toBe(429);
    expect(response.headers.get("retry-after")).toBe("1");
    expect(response.headers.get("x-ratelimit-remaining")).toBe("0");
  });

  it("returns JSON error body on 429", async () => {
    for (let i = 0; i < 100; i++) {
      proxy(mockApiRequest("/api/agents"));
    }
    const response = proxy(mockApiRequest("/api/agents"));
    const body = await response.json();
    expect(body).toEqual({ error: "Too many requests" });
  });

  it("applies stricter limits to auth routes", () => {
    // Auth limit is 20 burst
    for (let i = 0; i < 20; i++) {
      proxy(mockApiRequest("/api/auth/session"));
    }
    const response = proxy(mockApiRequest("/api/auth/session"));
    expect(response.status).toBe(429);
  });

  it("does not rate limit page routes", () => {
    for (let i = 0; i < 200; i++) {
      const response = proxy(mockPageRequest("/overview"));
      expect(response.status).toBe(200);
    }
  });

  it("sets X-RateLimit-Remaining header on allowed API requests", () => {
    const response = proxy(mockApiRequest("/api/secrets"));
    const remaining = response.headers.get("x-ratelimit-remaining");
    expect(remaining).toBeTruthy();
    const val = Number(remaining);
    expect(val).toBeLessThanOrEqual(100);
    expect(val).toBeGreaterThan(0);
  });

  it("isolates rate limits by IP", () => {
    // Exhaust bucket for IP A
    for (let i = 0; i < 100; i++) {
      proxy(mockApiRequest("/api/agents", "1.1.1.1"));
    }
    // IP A should be rate limited
    const responseA = proxy(mockApiRequest("/api/agents", "1.1.1.1"));
    expect(responseA.status).toBe(429);

    // IP B should still be allowed
    const responseB = proxy(mockApiRequest("/api/agents", "2.2.2.2"));
    expect(responseB.status).toBe(200);
  });
});
