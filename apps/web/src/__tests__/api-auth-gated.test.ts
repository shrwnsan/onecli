import { describe, it, expect, vi, beforeEach } from "vitest";

// Mock dependencies before importing route handlers
vi.mock("@/lib/api-auth", () => ({
  resolveApiAuth: vi.fn(),
}));

vi.mock("@/lib/api-utils", () => ({
  unauthorized: () =>
    new Response(JSON.stringify({ error: "Unauthorized" }), { status: 401 }),
}));

vi.mock("@/lib/gateway-ca", () => ({
  loadCaCertificate: vi.fn(
    () => "-----BEGIN CERTIFICATE-----\nMOCK_CA\n-----END CERTIFICATE-----",
  ),
}));

import { resolveApiAuth } from "@/lib/api-auth";
import { GET as getCa } from "@/app/api/gateway/ca/route";
import { GET as getHealth } from "@/app/api/health/route";

const mockAuthedRequest = () =>
  new Request("http://localhost:10254/api/gateway/ca", {
    headers: { authorization: "Bearer oc_test" },
  }) as unknown as import("next/server").NextRequest;

const mockUnauthedRequest = () =>
  new Request(
    "http://localhost:10254/api/gateway/ca",
  ) as unknown as import("next/server").NextRequest;

describe("GET /api/gateway/ca", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("returns 401 when no auth is provided", async () => {
    vi.mocked(resolveApiAuth).mockResolvedValue(null);
    const response = await getCa(mockUnauthedRequest());
    expect(response.status).toBe(401);
  });

  it("returns CA certificate when authenticated", async () => {
    vi.mocked(resolveApiAuth).mockResolvedValue({
      userId: "u1",
      accountId: "a1",
    });
    const response = await getCa(mockAuthedRequest());
    expect(response.status).toBe(200);
    expect(response.headers.get("content-type")).toBe("application/x-pem-file");
    expect(response.headers.get("content-disposition")).toContain(
      "onecli-gateway-ca.pem",
    );
  });
});

describe("GET /api/health", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("returns 401 when no auth is provided", async () => {
    vi.mocked(resolveApiAuth).mockResolvedValue(null);
    const response = await getHealth(mockUnauthedRequest());
    expect(response.status).toBe(401);
  });

  it("returns ok when authenticated", async () => {
    vi.mocked(resolveApiAuth).mockResolvedValue({
      userId: "u1",
      accountId: "a1",
    });
    const response = await getHealth(mockAuthedRequest());
    expect(response.status).toBe(200);
    const body = await response.json();
    expect(body.status).toBe("ok");
  });

  it("does not include timestamp in response", async () => {
    vi.mocked(resolveApiAuth).mockResolvedValue({
      userId: "u1",
      accountId: "a1",
    });
    const response = await getHealth(mockAuthedRequest());
    const body = await response.json();
    expect(body.timestamp).toBeUndefined();
  });
});
