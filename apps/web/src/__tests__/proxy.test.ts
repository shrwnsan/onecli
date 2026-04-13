import { describe, it, expect, vi } from "vitest";
import { proxy } from "@/proxy";

vi.mock("@/lib/env", () => ({
  IS_CLOUD: false,
  GOOGLE_CLIENT_ID: "",
  NEXTAUTH_SECRET: "",
  SECRET_ENCRYPTION_KEY: "test-key-for-testing",
}));

/**
 * Helper to create a mock NextRequest.
 * Only sets the fields used by proxy().
 */
const mockRequest = (pathname: string, headers: Record<string, string> = {}) =>
  ({
    nextUrl: { pathname },
    headers: new Headers(headers),
    url: `http://localhost:10254${pathname}`,
  }) as unknown as import("next/server").NextRequest;

describe("proxy — security headers on API routes", () => {
  it("sets X-Frame-Options: DENY on API responses", () => {
    const response = proxy(mockRequest("/api/agents"));
    expect(response.headers.get("X-Frame-Options")).toBe("DENY");
  });

  it("sets X-Content-Type-Options: nosniff on API responses", () => {
    const response = proxy(mockRequest("/api/secrets"));
    expect(response.headers.get("X-Content-Type-Options")).toBe("nosniff");
  });

  it("sets Referrer-Policy on API responses", () => {
    const response = proxy(mockRequest("/api/rules"));
    expect(response.headers.get("Referrer-Policy")).toBe(
      "strict-origin-when-cross-origin",
    );
  });

  it("sets Permissions-Policy on API responses", () => {
    const response = proxy(mockRequest("/api/agents"));
    const policy = response.headers.get("Permissions-Policy");
    expect(policy).toContain("camera=()");
    expect(policy).toContain("microphone=()");
    expect(policy).toContain("geolocation=()");
  });

  it("does NOT set security headers on non-API routes", () => {
    const response = proxy(mockRequest("/overview"));
    expect(response.headers.get("X-Frame-Options")).toBeNull();
    expect(response.headers.get("X-Content-Type-Options")).toBeNull();
  });
});

describe("proxy — CORS on API routes", () => {
  it("reflects Origin header when present", () => {
    const response = proxy(
      mockRequest("/api/agents", { origin: "https://app.example.com" }),
    );
    expect(response.headers.get("Access-Control-Allow-Origin")).toBe(
      "https://app.example.com",
    );
  });

  it("sets Vary: Origin when Origin is present", () => {
    const response = proxy(
      mockRequest("/api/agents", { origin: "https://app.example.com" }),
    );
    expect(response.headers.get("Vary")).toBe("Origin");
  });

  it("does NOT set Access-Control-Allow-Origin when no Origin header", () => {
    const response = proxy(mockRequest("/api/agents"));
    expect(response.headers.get("Access-Control-Allow-Origin")).toBeNull();
  });

  it("does NOT set Vary when no Origin header", () => {
    const response = proxy(mockRequest("/api/agents"));
    expect(response.headers.get("Vary")).toBeNull();
  });

  it("sets allowed methods", () => {
    const response = proxy(mockRequest("/api/agents"));
    expect(response.headers.get("Access-Control-Allow-Methods")).toBe(
      "GET, POST, PATCH, DELETE, OPTIONS",
    );
  });

  it("sets allowed headers", () => {
    const response = proxy(mockRequest("/api/agents"));
    expect(response.headers.get("Access-Control-Allow-Headers")).toBe(
      "Authorization, Content-Type",
    );
  });

  it("sets preflight cache max age", () => {
    const response = proxy(mockRequest("/api/agents"));
    expect(response.headers.get("Access-Control-Max-Age")).toBe("86400");
  });

  it("applies CORS to nested API routes", () => {
    const response = proxy(
      mockRequest("/api/apps/github/callback", {
        origin: "https://app.example.com",
      }),
    );
    expect(response.headers.get("Access-Control-Allow-Origin")).toBe(
      "https://app.example.com",
    );
  });

  it("applies security headers to nested API routes", () => {
    const response = proxy(mockRequest("/api/apps/github/callback"));
    expect(response.headers.get("X-Frame-Options")).toBe("DENY");
  });
});

describe("proxy — page routes unchanged", () => {
  it("passes through page routes when no setup error", () => {
    const response = proxy(mockRequest("/overview"));
    // Should not be a redirect
    expect(response.status).toBe(200);
  });
});
