import { NextResponse } from "next/server";
import type { NextRequest } from "next/server";
import {
  IS_CLOUD,
  GOOGLE_CLIENT_ID,
  NEXTAUTH_SECRET,
  SECRET_ENCRYPTION_KEY,
} from "@/lib/env";
import {
  checkRateLimit,
  getRateLimitKey,
  getRemainingTokens,
} from "@/lib/rate-limit";

/** Rate limit config for API routes: 100 burst, 10/sec sustained */
const API_RATE_LIMIT = { capacity: 100, refillRate: 10 } as const;

/** Rate limit config for auth routes: 20 burst, 2/sec sustained */
const AUTH_RATE_LIMIT = { capacity: 20, refillRate: 2 } as const;

type SetupErrorCode =
  | "oauth-misconfigured"
  | "missing-encryption-key"
  | "missing-nextauth-secret";

/**
 * Returns the first configuration error found, or null if setup is valid.
 */
const getSetupError = (): SetupErrorCode | null => {
  if (IS_CLOUD) return null;

  // NEXTAUTH_SECRET is set but Google OAuth creds are missing
  if (NEXTAUTH_SECRET && !GOOGLE_CLIENT_ID) {
    return "oauth-misconfigured";
  }

  // Google OAuth is configured but NEXTAUTH_SECRET is missing
  if (GOOGLE_CLIENT_ID && !NEXTAUTH_SECRET) {
    return "missing-nextauth-secret";
  }

  // SECRET_ENCRYPTION_KEY is required for encrypting secrets
  if (!SECRET_ENCRYPTION_KEY) {
    return "missing-encryption-key";
  }

  return null;
};

export const proxy = (request: NextRequest) => {
  const { pathname } = request.nextUrl;

  // ── API routes: CORS + security headers ─────────────────────────────
  if (pathname.startsWith("/api/")) {
    const response = NextResponse.next();

    // CORS
    const origin = request.headers.get("origin");
    if (origin) {
      response.headers.set("Access-Control-Allow-Origin", origin);
      response.headers.set("Vary", "Origin");
    }
    response.headers.set(
      "Access-Control-Allow-Methods",
      "GET, POST, PATCH, DELETE, OPTIONS",
    );
    response.headers.set(
      "Access-Control-Allow-Headers",
      "Authorization, Content-Type",
    );
    response.headers.set("Access-Control-Max-Age", "86400");

    // Security headers
    response.headers.set("X-Frame-Options", "DENY");
    response.headers.set("X-Content-Type-Options", "nosniff");
    response.headers.set("Referrer-Policy", "strict-origin-when-cross-origin");
    response.headers.set(
      "Permissions-Policy",
      "camera=(), microphone=(), geolocation=()",
    );

    return response;
  }

  // ── Page routes: setup error redirect ────────────────────────────────
  const error = getSetupError();

  if (pathname.startsWith("/setup-error")) {
    if (!error) {
      return NextResponse.redirect(new URL("/auth/login", request.url));
    }
    return NextResponse.next();
  }

  if (error) {
    return NextResponse.redirect(
      new URL(`/setup-error?code=${error}`, request.url),
    );
  }

  // Rate limit API routes
  if (pathname.startsWith("/api/")) {
    const key = getRateLimitKey(request);
    const isAuthRoute = pathname.startsWith("/api/auth/");
    const limit = isAuthRoute ? AUTH_RATE_LIMIT : API_RATE_LIMIT;

    if (!checkRateLimit(key, limit)) {
      return NextResponse.json(
        { error: "Too many requests" },
        {
          status: 429,
          headers: {
            "Retry-After": "1",
            "X-RateLimit-Remaining": "0",
          },
        },
      );
    }

    const response = NextResponse.next();
    response.headers.set(
      "X-RateLimit-Remaining",
      String(getRemainingTokens(key, limit)),
    );
    return response;
  }

  return NextResponse.next();
};

export const config = {
  matcher: [
    // Match all routes except static files and images
    "/((?!_next/static|_next/image|favicon.ico|.*\\.).*)",
  ],
};
