# Eval 001 — OneCLI Web App Security Review

**Date:** 2026-04-02
**Scope:** `apps/web/`, `packages/db/`, `docker/`
**Reviewer:** Security audit (whitehat)

---

## Executive Summary

Comprehensive security review of the OneCLI web application. The codebase demonstrates solid fundamentals — AES-256-GCM encryption, proper auth scoping, Zod validation on all inputs, timing-safe comparisons, HMAC CSRF protection, and clean separation of concerns. 16 findings were identified: 4 HIGH, 7 MEDIUM, 5 LOW. 13 of these have never been discussed upstream; 2 have partial upstream coverage; 1 has adjacent discussion.

### What's Done Well

| Area | Implementation |
|------|---------------|
| **Encryption** | AES-256-GCM with proper IV, auth tag, and key validation |
| **Input Validation** | Zod schemas on every API and server action endpoint |
| **Auth Scoping** | Every query filters by `accountId` — no horizontal privilege escalation |
| **CSRF (OAuth)** | HMAC-SHA256 signed state with timing-safe comparison |
| **Audit Logging** | Comprehensive audit trail on all state-changing operations |
| **Secret Handling** | Plaintext secrets are never returned in API responses; preview is masked |
| **No SQL Injection** | Uses Prisma parameterized queries exclusively; no raw SQL |
| **No XSS Vectors** | No `dangerouslySetInnerHTML`, no `innerHTML`, no `eval()` |
| **Separation of Concerns** | Clean service/action/API layering with auth checks at every boundary |
| **Error Handling** | Internal errors caught and return generic 500; no stack traces leaked |

### Findings Summary

| # | Severity | Title | Upstream Status |
|---|----------|-------|-----------------|
| 001 | 🔴 HIGH | API Keys Stored in Plaintext | Never discussed |
| 002 | 🔴 HIGH | Agent Access Tokens Stored in Plaintext | Never discussed |
| 003 | 🔴 HIGH | No CORS on Web App API Routes | Partially addressed (gateway only — PR #52) |
| 004 | 🔴 HIGH | Missing Security Headers | Never discussed |
| 005 | 🟠 MEDIUM | No Rate Limiting on Auth/API Routes | Never discussed |
| 006 | 🟠 MEDIUM | Weak NextAuth Fallback Secret | Never discussed |
| 007 | 🟠 MEDIUM | Unauthenticated CA Certificate Endpoint | Never discussed |
| 008 | 🟠 MEDIUM | Unauthenticated Health Endpoint | Never discussed |
| 009 | 🟠 MEDIUM | OAuth Nonce Replay | Never discussed (HMAC CSRF in PR #127, replay not addressed) |
| 010 | 🟠 MEDIUM | Legacy `ConnectedService` Plaintext Tokens | Partially addressed (PR #146 encrypts VaultConnection only) |
| 011 | 🟠 MEDIUM | No UUID Validation on Route Parameters | Never discussed |
| 012 | 🟡 LOW | Demo Secret Value Hardcoded | Never discussed |
| 013 | 🟡 LOW | `force-dynamic` Disables Static Rendering | Never discussed |
| 014 | 🟡 LOW | Error Messages Could Leak Implementation Details | Never discussed |
| 015 | 🟡 LOW | `localUserEnsured` Flag Not Process-Safe | Never discussed |
| 016 | 🟡 LOW | No IP Address in Audit Logs | Adjacent discussion (Issue #54, PR #103 — no IP) |

### Recommended Remediation Order

1. Hash API keys and agent access tokens in the database (#001, #002)
2. Add security headers (CSP, HSTS, X-Frame-Options) (#004)
3. Add CORS policy to web app API routes (#003)
4. Add rate limiting on auth and API key endpoints (#005)
5. Fix the NextAuth fallback secret to never be a static string (#006)
6. Add nonce replay protection to OAuth callbacks (#009)
7. Authenticate the CA certificate endpoint (#007)
8. Add IP addresses to audit logs (#016)
9. Clean up or migrate plaintext tokens in `ConnectedService` (#010)
10. Add UUID validation on route parameters (#011)

---

## 🔴 HIGH Severity

### 001 — API Keys Stored in Plaintext (No Hashing)

**Files:** `apps/web/src/lib/validate-api-key.ts`, `apps/web/src/lib/services/api-key-service.ts`, `packages/db/prisma/schema.prisma`

The `ApiKey.key` field stores the full `oc_...` token as plaintext in the database. Lookups use a direct `findUnique({ where: { key: token } })` query. If the database is ever compromised (SQL injection, backup leak, insider threat, stolen replica), every user's API key is immediately usable — no further cracking required.

**Upstream:** Never discussed. No issue, PR, or commit mentions hashing API keys.

**Recommendation:** Store a SHA-256 hash of the key in the database. During creation, generate the key, hash it, store the hash, and return the plaintext to the user **once**. Validation compares `SHA-256(supplied_token)` against the stored hash.

```typescript
// generateApiKey() returns the plaintext (shown once to user)
// db stores: keyHash = SHA-256(key)
// validateApiKey: findUnique({ where: { keyHash: SHA-256(supplied_token) } })
```

---

### 002 — Agent Access Tokens Stored in Plaintext

**Files:** `apps/web/src/lib/services/agent-service.ts:10`, `packages/db/prisma/schema.prisma`

Same issue as #001 but for agent `accessToken` values (`aoc_...`). These tokens grant access to the proxy gateway and are stored as plaintext in the `Agent` table. A database breach exposes all gateway access tokens immediately.

**Upstream:** Never discussed.

**Recommendation:** Two options:

1. **Hash (preferred):** Same strategy as API keys — store SHA-256 hash, return plaintext once. Requires changes to the gateway's token validation (Rust side) as well.
2. **Encrypt:** At minimum, encrypt with the existing `cryptoService` (AES-256-GCM) so a DB breach doesn't immediately expose tokens. Less ideal since the gateway needs to decrypt on every request.

---

### 003 — No CORS Configuration on Web App API Routes

**Files:** All route handlers under `apps/web/src/app/api/`

There is zero CORS configuration on any Next.js API route. This means any website can make authenticated API requests if the user has an active session cookie (browsers send cookies cross-origin unless `SameSite=Strict`).

**Upstream:** Partially addressed. PR [#52](https://github.com/onecli/onecli/pull/52) ("fix: add gateway auth extractor, CORS, and user_id threading") added CORS — but **only to the Rust gateway**, not the Next.js web app API routes.

**Recommendation:** Add explicit CORS headers via Next.js middleware:

```typescript
// middleware.ts
export function middleware(request: NextRequest) {
  const response = NextResponse.next();
  response.headers.set("Access-Control-Allow-Origin", "https://your-app-domain.com");
  response.headers.set("Access-Control-Allow-Methods", "GET, POST, PATCH, DELETE, OPTIONS");
  response.headers.set("Access-Control-Allow-Headers", "Authorization, Content-Type");
  response.headers.set("Access-Control-Allow-Credentials", "true");
  return response;
}
```

Also ensure the NextAuth session cookie uses `SameSite=Strict` or `SameSite=Lax`.

---

### 004 — Missing Security Headers (CSP, HSTS, X-Frame-Options)

**Files:** `apps/web/src/proxy.ts`, `apps/web/next.config.js`

No security headers are set anywhere. The app is vulnerable to:

- **Clickjacking** — no `X-Frame-Options` or `frame-ancestors` CSP directive
- **MIME sniffing** — no `X-Content-Type-Options: nosniff`
- **Protocol downgrade** — no `Strict-Transport-Security` in production
- **XSS without CSP** — no `Content-Security-Policy`

**Upstream:** Never discussed. No issue or PR mentions CSP, HSTS, X-Frame-Options, or security headers.

**Recommendation:** Add headers in `next.config.js`:

```js
headers: async () => [{
  source: '/(.*)',
  headers: [
    { key: 'X-Frame-Options', value: 'DENY' },
    { key: 'X-Content-Type-Options', value: 'nosniff' },
    { key: 'Referrer-Policy', value: 'strict-origin-when-cross-origin' },
    { key: 'Permissions-Policy', value: 'camera=(), microphone=(), geolocation=()' },
    { key: 'Strict-Transport-Security', value: 'max-age=63072000; includeSubDomains; preload' },
    { key: 'Content-Security-Policy', value: "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'" },
  ]
}]
```

Note: CSP will need careful tuning since the app uses Next.js (inline scripts/styles), Tailwind, Google Fonts, and potentially third-party assets.

---

## 🟠 MEDIUM Severity

### 005 — No Rate Limiting on Authentication and API Routes

**Files:** All route handlers under `apps/web/src/app/api/`

No rate limiting on any web app endpoint:

- `/api/auth/session` — called on every dashboard mount
- All API key-authenticated routes
- OAuth callback endpoints
- Secret CRUD operations

**Upstream:** Not addressed for the web app. Rate limiting exists only as a **policy rule feature** for end-user gateway traffic (PR [#84](https://github.com/onecli/onecli/pull/84)), not as server-side protection for the web app's own endpoints.

**Recommendation:** Add rate limiting middleware. `@upstash/ratelimit` works well with Next.js edge runtime. At minimum protect `/api/auth/session`, API key auth routes, OAuth callbacks, and all mutating routes.

---

### 006 — Weak NextAuth Fallback Secret

**File:** `apps/web/src/lib/auth/nextauth-config.ts:13`

```typescript
secret: process.env.NEXTAUTH_SECRET || "local-mode-fallback-unused",
```

If someone deploys with `NEXTAUTH_SECRET` unset and Google OAuth accidentally configured, the JWT secret becomes the hardcoded string `"local-mode-fallback-unused"` — publicly visible in source code. An attacker could forge JWTs and impersonate any user.

**Upstream:** Never discussed.

**Recommendation:** Either throw an error when `GOOGLE_CLIENT_ID` is set but `NEXTAUTH_SECRET` isn't, or auto-generate a random secret at container startup (same pattern as `SECRET_ENCRYPTION_KEY` in `docker/entrypoint.sh`).

---

### 007 — Unauthenticated CA Certificate Endpoint

**Files:** `apps/web/src/app/api/gateway/ca/route.ts`, `apps/web/src/lib/gateway-ca.ts`

`GET /api/gateway/ca` serves the gateway's CA certificate to any unauthenticated request. While not inherently secret, it enables discovery of the gateway's trust domain and could be used to set up MITM positions.

**Upstream:** Never discussed.

**Recommendation:** Require authentication. The container config endpoint (`/api/container-config`) already requires auth and returns the CA inline — the standalone CA endpoint should do the same.

---

### 008 — Unauthenticated Health Endpoint

**File:** `apps/web/src/app/api/health/route.ts`

`GET /api/health` is unauthenticated and returns a status + timestamp, leaking deployment existence and server clock information.

**Upstream:** Never discussed.

**Recommendation:** Restrict to internal networks, require a shared secret as a query parameter, or move behind auth.

---

### 009 — OAuth Nonce Replay (No Server-Side Tracking)

**Files:** `apps/web/src/lib/oauth-state.ts`, `apps/web/src/app/api/connections/[provider]/callback/route.ts`

The OAuth state includes a nonce signed with HMAC-SHA256 to prevent tampering, but there's no server-side tracking to ensure each nonce is used exactly once. If an attacker captures the `state` parameter before the legitimate callback, they could replay it and steal exchanged tokens.

**Upstream:** Never discussed. HMAC-based CSRF state was introduced in PR [#127](https://github.com/onecli/onecli/pull/127), but nonce replay is unaddressed.

**Recommendation:** Store nonces server-side with a short TTL. On callback, check the nonce exists and delete it. Reject already-used or expired nonces.

```typescript
// Before redirect: store nonce
await storeNonce(state.nonce, { accountId, provider, expiresAt: now + 10min });

// On callback: consume nonce
const nonceData = await consumeNonce(state.nonce);
if (!nonceData) return errorRedirect("Invalid or expired state");
```

---

### 010 — Legacy `ConnectedService` Model Stores Tokens in Plaintext

**File:** `packages/db/prisma/schema.prisma:243-244`

```prisma
accessToken  String?
refreshToken String?
```

The `ConnectedService` model stores OAuth tokens as plaintext. The newer `AppConnection` model correctly encrypts credentials, but `ConnectedService` was never migrated.

**Upstream:** Partially addressed. Open PR [#146](https://github.com/onecli/onecli/pull/146) encrypts `connection_data` in `VaultConnection`, but `ConnectedService` with plaintext `accessToken`/`refreshToken` remains untouched.

**Recommendation:** Audit whether any code still writes to `ConnectedService`. If unused, remove the model. If still needed, migrate to the encrypted pattern used by `AppConnection.credentials`.

---

### 011 — No UUID Validation on Route Parameters

**Files:** `apps/web/src/app/api/agents/[agentId]/route.ts`, `apps/web/src/app/api/secrets/[secretId]/route.ts`, `apps/web/src/app/api/rules/[ruleId]/route.ts`, `apps/web/src/app/api/connections/[provider]/route.ts`

Dynamic route params are passed directly to service functions without validating format. While Prisma won't match malformed IDs (returning 404), this allows probing of resource identifier formats and sends arbitrary strings to queries.

**Upstream:** Never discussed.

**Recommendation:** Add UUID validation in route handlers:

```typescript
const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const { agentId } = await params;
if (!UUID_REGEX.test(agentId)) {
  return NextResponse.json({ error: "Invalid ID format" }, { status: 400 });
}
```

---

## 🟡 LOW Severity

### 012 — Demo Secret Value Hardcoded

**File:** `apps/web/src/lib/constants.ts`

```typescript
export const DEMO_SECRET_VALUE = "WELCOME-TO-ONECLI-SECRETS-ARE-WORKING";
```

Encrypted and stored in the DB; plaintext never returned to the client. Not exploitable, but plaintext exists in source code.

**Upstream:** Never discussed. **Recommendation:** Low priority. Could move to an environment variable or generate randomly on first seed.

---

### 013 — `force-dynamic` Layout Disables Static Rendering

**File:** `apps/web/src/app/layout.tsx:35`

`export const dynamic = "force-dynamic"` forces server-side rendering on every request to read the runtime auth config. This eliminates Next.js's static optimization, ISR, and edge caching, increasing the attack surface for DoS.

**Upstream:** Never discussed. **Recommendation:** Use `unstable_noStore()` only in components that need dynamic data, allowing the rest to be cached. The runtime config is already cached in memory after first read in `runtime-config.ts`.

---

### 014 — Error Messages Could Leak Implementation Details

**Files:** `apps/web/src/lib/services/errors.ts`, `apps/web/src/lib/api-utils.ts`

`ServiceError` messages pass through to API clients verbatim (e.g., `"Agent with this identifier already exists"`, `"Provider not configured"`). These can confirm resource existence and reveal internal structure. Unknown errors correctly return generic `"Internal server error"`.

**Upstream:** Never discussed. **Recommendation:** Consider whether 404 messages should be generic to prevent ID enumeration. Low-priority defense-in-depth.

---

### 015 — `localUserEnsured` Flag Not Process-Safe

**File:** `apps/web/src/lib/auth/auth-server.ts:14`

An in-memory flag guards against duplicate local user provisioning, but Next.js runs multiple server processes in production. The flag is per-process, so two processes could both attempt the upsert. Prisma's `upsert` handles this safely (no corruption), but the flag is misleading.

**Upstream:** Never discussed. **Recommendation:** Remove the flag and rely on Prisma's `upsert` for idempotency. Low impact.

---

### 016 — No IP Address in Audit Logs

**File:** `apps/web/src/lib/services/audit-service.ts`

Audit logs capture `userId`, `accountId`, `action`, `service`, and `metadata` — but not client IP. For a security-sensitive system managing API keys and secrets, IP logging is valuable for forensic analysis and compliance (HIPAA, SOC 2).

**Upstream:** Adjacent discussion exists. Issue [#54](https://github.com/onecli/onecli/issues/54) requested audit logging (HIPAA mentioned). PR [#103](https://github.com/onecli/onecli/pull/103) implemented the audit trail but did not include IP addresses.

**Recommendation:** Add an optional `ipAddress` field to `AuditEventParams` and the `audit_logs` table. Extract from `x-forwarded-for` or `x-real-ip` headers in the API route layer.

```typescript
const ip = request.headers.get("x-forwarded-for")?.split(",")[0]?.trim()
  ?? request.headers.get("x-real-ip");
```
