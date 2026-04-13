import { describe, it, expect, vi } from "vitest";

// We test getSetupError by importing proxy and checking redirect behavior.
// The function is not exported, so we test it indirectly via the proxy output.

vi.mock("@/lib/env", () => ({
  IS_CLOUD: false,
  GOOGLE_CLIENT_ID: "",
  NEXTAUTH_SECRET: "",
  SECRET_ENCRYPTION_KEY: "test-key",
}));

const mockRequest = (pathname: string) =>
  ({
    nextUrl: { pathname },
    headers: new Headers(),
    url: `http://localhost:10254${pathname}`,
  }) as unknown as import("next/server").NextRequest;

/**
 * Helper: get the redirect URL from a proxy response, or null if not a redirect.
 */
const getRedirectUrl = (response: Response): string | null => {
  const location = response.headers.get("location");
  return location;
};

describe("proxy — missing-nextauth-secret setup error", () => {
  it("redirects to setup-error when GOOGLE_CLIENT_ID is set but NEXTAUTH_SECRET is empty", async () => {
    // The proxy function reads env at call time via the imported constants.
    // We use vi.resetModules + dynamic import to test with different env values.

    vi.doMock("@/lib/env", () => ({
      IS_CLOUD: false,
      GOOGLE_CLIENT_ID: "abc.apps.googleusercontent.com",
      NEXTAUTH_SECRET: "",
      SECRET_ENCRYPTION_KEY: "test-key",
    }));

    const { proxy: proxyWithGoogleNoSecret } = await import("@/proxy");

    const response = proxyWithGoogleNoSecret(mockRequest("/overview"));
    const url = getRedirectUrl(response);
    expect(url).toContain("/setup-error");
    expect(url).toContain("missing-nextauth-secret");

    vi.resetModules();
  });

  it("does not redirect when both GOOGLE_CLIENT_ID and NEXTAUTH_SECRET are set", async () => {
    vi.resetModules();

    vi.doMock("@/lib/env", () => ({
      IS_CLOUD: false,
      GOOGLE_CLIENT_ID: "abc.apps.googleusercontent.com",
      NEXTAUTH_SECRET: "a-real-secret-value",
      SECRET_ENCRYPTION_KEY: "test-key",
    }));

    const { proxy: proxyWithBothSet } = await import("@/proxy");

    const response = proxyWithBothSet(mockRequest("/overview"));
    // Should not redirect — passes through
    expect(getRedirectUrl(response)).toBeNull();

    vi.resetModules();
  });

  it("does not redirect when neither is set (local mode)", async () => {
    const { proxy: proxyLocal } = await import("@/proxy");
    const response = proxyLocal(mockRequest("/overview"));
    expect(getRedirectUrl(response)).toBeNull();
  });

  it("still detects oauth-misconfigured (secret set, no client)", async () => {
    vi.resetModules();

    vi.doMock("@/lib/env", () => ({
      IS_CLOUD: false,
      GOOGLE_CLIENT_ID: "",
      NEXTAUTH_SECRET: "some-secret",
      SECRET_ENCRYPTION_KEY: "test-key",
    }));

    const { proxy: proxyWithSecretNoGoogle } = await import("@/proxy");

    const response = proxyWithSecretNoGoogle(mockRequest("/overview"));
    const url = getRedirectUrl(response);
    expect(url).toContain("oauth-misconfigured");

    vi.resetModules();
  });
});
