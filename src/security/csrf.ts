/**
 * CSRF (Cross-Site Request Forgery) Protection Module
 *
 * OWASP A01:2021 - Broken Access Control
 * SEC-004: CSRF protection for state-changing operations
 *
 * Implements Double Submit Cookie pattern:
 * 1. Server sets CSRF token in cookie (not httpOnly, so JS can read it)
 * 2. Client reads cookie and sends token in header or form field
 * 3. Server validates that cookie value matches header/form value
 *
 * @module src/security/csrf
 */

import type { IncomingMessage, ServerResponse } from "node:http";
import crypto from "node:crypto";
import { createSubsystemLogger } from "../logging/subsystem.js";
import { type CsrfTokenStore, createCsrfStoreFromEnv, MemoryCsrfStore } from "./csrf-store.js";

const log = createSubsystemLogger("security/csrf");

/** CSRF token cookie name */
export const CSRF_COOKIE_NAME = "XSRF-TOKEN";

/** CSRF token header name */
export const CSRF_HEADER_NAME = "x-csrf-token";

/** CSRF token form field name */
export const CSRF_FORM_FIELD = "_csrf";

/** Safe HTTP methods that don't require CSRF protection */
const SAFE_METHODS = new Set(["GET", "HEAD", "OPTIONS", "TRACE"]);

/** Token length in bytes */
const TOKEN_LENGTH = 32;

/** CSRF token storage - defaults to memory, can be configured for persistence */
let tokenStore: CsrfTokenStore = new MemoryCsrfStore();
let storeInitialized = false;

/** Token expiration time (24 hours) */
const TOKEN_EXPIRY_MS = 24 * 60 * 60 * 1000;

/** Cleanup interval for expired tokens (5 minutes) */
const CLEANUP_INTERVAL_MS = 5 * 60 * 1000;

/**
 * Generate a cryptographically secure CSRF token
 * @returns Base64 encoded random token
 */
export function generateCsrfToken(): string {
  return crypto.randomBytes(TOKEN_LENGTH).toString("base64url");
}

/**
 * Get or create CSRF token for a session
 * @param sessionId - Unique session identifier
 * @returns CSRF token string
 */
export async function getOrCreateCsrfToken(sessionId: string): Promise<string> {
  await ensureStoreInitialized();

  const existing = await tokenStore.get(sessionId);
  if (existing) {
    return existing.token;
  }

  const token = generateCsrfToken();
  await tokenStore.set({
    sessionId,
    token,
    expiresAt: Date.now() + TOKEN_EXPIRY_MS,
  });

  return token;
}

/**
 * Validate CSRF token for a session
 * @param sessionId - Unique session identifier
 * @param token - Token to validate
 * @returns true if valid, false otherwise
 */
export async function validateCsrfToken(sessionId: string, token: string): Promise<boolean> {
  await ensureStoreInitialized();
  return tokenStore.validate(sessionId, token);
}

/**
 * Clear CSRF token for a session (logout)
 * @param sessionId - Unique session identifier
 */
export async function clearCsrfToken(sessionId: string): Promise<void> {
  await ensureStoreInitialized();
  await tokenStore.delete(sessionId);
}

/**
 * Clean up expired tokens (should be called periodically)
 */
export async function cleanupExpiredTokens(): Promise<number> {
  await ensureStoreInitialized();
  return tokenStore.cleanup();
}

/**
 * Ensure the token store is initialized
 * Initializes from environment on first call
 */
async function ensureStoreInitialized(): Promise<void> {
  if (storeInitialized) {
    return;
  }

  try {
    tokenStore = await createCsrfStoreFromEnv();
    storeInitialized = true;
    log.info(`CSRF token store initialized: ${tokenStore.name}`);
  } catch (err) {
    log.error("Failed to initialize CSRF token store, using memory fallback", { err });
    tokenStore = new MemoryCsrfStore();
    storeInitialized = true;
  }
}

// Start periodic cleanup
setInterval(() => {
  cleanupExpiredTokens().catch((err) => {
    log.error("CSRF token cleanup failed", { err });
  });
}, CLEANUP_INTERVAL_MS);

/**
 * Extract session ID from request (using IP + User-Agent hash as fallback)
 * In production, use proper session management
 * @param req - HTTP request
 * @returns Session ID string
 */
export function extractSessionId(req: IncomingMessage): string {
  // Try to get from custom header first (for authenticated sessions)
  const headers = req.headers || {};
  const authHeader = headers["x-session-id"] as string | undefined;
  if (authHeader) {
    return authHeader;
  }

  // Fallback: hash of IP + User-Agent
  const ip = req.socket?.remoteAddress ?? "unknown";
  const userAgent = headers["user-agent"] ?? "unknown";
  const data = `${ip}:${userAgent}`;

  return crypto.createHash("sha256").update(data).digest("hex").slice(0, 32);
}

/**
 * Get CSRF token from request (header, form body, or query)
 * @param req - HTTP request
 * @returns Token string or null
 */
export function extractCsrfTokenFromRequest(req: IncomingMessage): string | null {
  // Check header first
  const headerToken = req.headers[CSRF_HEADER_NAME.toLowerCase()];
  if (typeof headerToken === "string" && headerToken) {
    return headerToken;
  }

  // Check query parameter (for GET requests that need validation)
  try {
    const url = new URL(req.url ?? "/", "http://localhost");
    const queryToken = url.searchParams.get(CSRF_FORM_FIELD);
    if (queryToken) {
      return queryToken;
    }
  } catch {
    // Invalid URL, continue
  }

  return null;
}

/**
 * Get CSRF token from cookie
 * @param req - HTTP request
 * @returns Token string or null
 */
export function getCsrfTokenFromCookie(req: IncomingMessage): string | null {
  const cookieHeader = req.headers.cookie;
  if (!cookieHeader) {
    return null;
  }

  const cookies = parseCookies(cookieHeader);
  return cookies[CSRF_COOKIE_NAME] ?? null;
}

/**
 * Parse cookie header into object
 * @param cookieHeader - Raw cookie header string
 * @returns Object with cookie names as keys
 */
function parseCookies(cookieHeader: string): Record<string, string> {
  const cookies: Record<string, string> = {};

  for (const cookie of cookieHeader.split(";")) {
    const [name, ...rest] = cookie.trim().split("=");
    if (name && rest.length > 0) {
      cookies[name] = decodeURIComponent(rest.join("="));
    }
  }

  return cookies;
}

/**
 * Set CSRF token cookie
 * @param res - HTTP response
 * @param token - CSRF token to set
 * @param options - Cookie options
 */
export function setCsrfCookie(
  res: ServerResponse,
  token: string,
  options: { secure?: boolean; sameSite?: "strict" | "lax" | "none" } = {},
): void {
  const { secure = false, sameSite = "strict" } = options;

  // Note: httpOnly is false so JavaScript can read the cookie
  // This is required for Double Submit Cookie pattern
  const cookieValue = `${CSRF_COOKIE_NAME}=${encodeURIComponent(token)}; Path=/; Max-Age=${TOKEN_EXPIRY_MS / 1000}; SameSite=${sameSite}${secure ? "; Secure" : ""}`;

  const existingCookies = res.getHeader("Set-Cookie");
  if (Array.isArray(existingCookies)) {
    res.setHeader("Set-Cookie", [...existingCookies, cookieValue]);
  } else if (typeof existingCookies === "string") {
    res.setHeader("Set-Cookie", [existingCookies, cookieValue]);
  } else {
    res.setHeader("Set-Cookie", cookieValue);
  }
}

/**
 * Clear CSRF token cookie
 * @param res - HTTP response
 */
export function clearCsrfCookie(res: ServerResponse): void {
  const cookieValue = `${CSRF_COOKIE_NAME}=; Path=/; Max-Age=0; SameSite=strict`;

  const existingCookies = res.getHeader("Set-Cookie");
  if (Array.isArray(existingCookies)) {
    res.setHeader("Set-Cookie", [...existingCookies, cookieValue]);
  } else if (typeof existingCookies === "string") {
    res.setHeader("Set-Cookie", [existingCookies, cookieValue]);
  } else {
    res.setHeader("Set-Cookie", cookieValue);
  }
}

/** CSRF validation result */
export type CsrfValidationResult = { valid: true } | { valid: false; reason: string };

/**
 * Validate CSRF token from request against cookie
 * Implements Double Submit Cookie pattern
 * @param req - HTTP request
 * @returns Validation result
 */
export async function validateCsrfTokenFromRequest(
  req: IncomingMessage,
): Promise<CsrfValidationResult> {
  // Safe methods don't require CSRF protection
  if (SAFE_METHODS.has(req.method ?? "GET")) {
    return { valid: true };
  }

  await ensureStoreInitialized();

  const cookieToken = getCsrfTokenFromCookie(req);
  if (!cookieToken) {
    return { valid: false, reason: "CSRF cookie missing" };
  }

  const requestToken = extractCsrfTokenFromRequest(req);
  if (!requestToken) {
    return { valid: false, reason: "CSRF token missing in request" };
  }

  // Compare cookie value with request token (Double Submit Cookie)
  try {
    const cookieBuf = Buffer.from(cookieToken);
    const requestBuf = Buffer.from(requestToken);

    if (cookieBuf.length !== requestBuf.length) {
      return { valid: false, reason: "CSRF token mismatch" };
    }

    if (!crypto.timingSafeEqual(cookieBuf, requestBuf)) {
      return { valid: false, reason: "CSRF token mismatch" };
    }

    return { valid: true };
  } catch {
    return { valid: false, reason: "CSRF token validation error" };
  }
}

/** Options for CSRF middleware */
export interface CsrfMiddlewareOptions {
  /** Paths to exclude from CSRF protection */
  excludedPaths?: string[];
  /** Whether to use secure cookies */
  secure?: boolean;
  /** SameSite cookie attribute */
  sameSite?: "strict" | "lax" | "none";
  /** Custom error handler */
  onError?: (req: IncomingMessage, res: ServerResponse, reason: string) => void;
}

/**
 * CSRF protection middleware
 * @param options - Middleware options
 * @returns Middleware function
 */
export function csrfProtection(options: CsrfMiddlewareOptions = {}) {
  const { excludedPaths = [], secure = false, sameSite = "strict", onError } = options;

  return async (req: IncomingMessage, res: ServerResponse, next: () => void): Promise<void> => {
    const pathname = new URL(req.url ?? "/", "http://localhost").pathname;

    // Check if path is excluded
    if (excludedPaths.some((path) => pathname.startsWith(path))) {
      next();
      return;
    }

    // Ensure store is initialized
    await ensureStoreInitialized();

    // Safe methods: set cookie if not present
    if (SAFE_METHODS.has(req.method ?? "GET")) {
      const existingToken = getCsrfTokenFromCookie(req);
      if (!existingToken) {
        const sessionId = extractSessionId(req);
        const token = await getOrCreateCsrfToken(sessionId);
        setCsrfCookie(res, token, { secure, sameSite });
      }
      next();
      return;
    }

    // State-changing methods: validate token
    const validation = await validateCsrfTokenFromRequest(req);

    if (!validation.valid) {
      if (onError) {
        onError(req, res, validation.reason);
      } else {
        res.statusCode = 403;
        res.setHeader("Content-Type", "application/json; charset=utf-8");
        res.end(
          JSON.stringify({
            error: "CSRF validation failed",
            message: validation.reason,
          }),
        );
      }
      return;
    }

    next();
  };
}

/**
 * Generate HTML meta tag with CSRF token for forms
 * @param token - CSRF token
 * @returns HTML meta tag string
 */
export function generateCsrfMetaTag(token: string): string {
  return `<meta name="csrf-token" content="${escapeHtml(token)}">`;
}

/**
 * Generate JavaScript to read CSRF token from cookie
 * @returns JavaScript code string
 */
export function generateCsrfTokenScript(): string {
  return `
<script>
(function() {
  window.__OPENCLAW_CSRF_TOKEN__ = (function() {
    const match = document.cookie.match(new RegExp('(^| )${CSRF_COOKIE_NAME}=([^;]+)'));
    return match ? decodeURIComponent(match[2]) : null;
  })();
  window.__OPENCLAW_CSRF_HEADER__ = ${JSON.stringify(CSRF_HEADER_NAME)};
})();
</script>`;
}

/**
 * Escape HTML special characters
 * @param text - Text to escape
 * @returns Escaped text
 */
/**
 * Configure the CSRF token store
 * Use this to set a custom store (e.g., Redis for distributed deployments)
 * @param store - CSRF token store implementation
 */
export function configureCsrfStore(store: CsrfTokenStore): void {
  tokenStore = store;
  storeInitialized = true;
  log.info(`CSRF token store configured: ${store.name}`);
}

/**
 * Get the current CSRF token store (for testing/monitoring)
 * @returns Current token store
 */
export function getCsrfTokenStore(): CsrfTokenStore {
  return tokenStore;
}

function escapeHtml(text: string): string {
  const div = typeof document !== "undefined" ? document.createElement("div") : null;
  if (div) {
    div.textContent = text;
    return div.innerHTML;
  }
  // Server-side fallback
  return text
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}
