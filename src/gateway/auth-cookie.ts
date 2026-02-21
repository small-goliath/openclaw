/**
 * httpOnly 쿠키 기반 인증 관리 (서버 측)
 * XSS 공격으로부터 토큰을 보호하기 위해 httpOnly 쿠키 사용
 */

import type { IncomingMessage, ServerResponse } from "node:http";
import crypto from "node:crypto";
import { safeEqualSecret } from "../security/secret-equal.js";

/**
 * JWT 토큰 페이로드
 */
export interface TokenPayload {
  userId: string;
  sessionId: string;
  type: "access" | "refresh";
  iat: number;
  exp: number;
}

/**
 * 쿠키 설정 옵션
 */
interface CookieOptions {
  httpOnly: boolean;
  secure: boolean;
  sameSite: "strict" | "lax" | "none";
  maxAge: number;
  path: string;
}

/**
 * JWT 비밀 키 (환경 변수에서 로드)
 */
function getJwtSecret(): string {
  const secret = process.env.OPENCLAW_JWT_SECRET;
  if (!secret) {
    // 개발 환경에서만 기본값 사용
    if (process.env.NODE_ENV === "development") {
      return "dev-secret-do-not-use-in-production";
    }
    throw new Error("OPENCLAW_JWT_SECRET environment variable is required");
  }
  return secret;
}

/**
 * JWT 토큰 생성
 */
export function generateToken(
  payload: Omit<TokenPayload, "iat" | "exp">,
  expiresInSeconds: number,
): string {
  const secret = getJwtSecret();
  const header = { alg: "HS256", typ: "JWT" };
  const now = Math.floor(Date.now() / 1000);
  const fullPayload = {
    ...payload,
    iat: now,
    exp: now + expiresInSeconds,
  };

  const encodedHeader = Buffer.from(JSON.stringify(header)).toString("base64url");
  const encodedPayload = Buffer.from(JSON.stringify(fullPayload)).toString("base64url");
  const signature = crypto
    .createHmac("sha256", secret)
    .update(`${encodedHeader}.${encodedPayload}`)
    .digest("base64url");

  return `${encodedHeader}.${encodedPayload}.${signature}`;
}

/**
 * JWT 토큰 검증
 */
export function verifyToken(token: string): TokenPayload | null {
  try {
    const secret = getJwtSecret();
    const [encodedHeader, encodedPayload, signature] = token.split(".");

    if (!encodedHeader || !encodedPayload || !signature) {
      return null;
    }

    // 서명 검증
    const expectedSignature = crypto
      .createHmac("sha256", secret)
      .update(`${encodedHeader}.${encodedPayload}`)
      .digest("base64url");

    if (!safeEqualSecret(signature, expectedSignature)) {
      return null;
    }

    const payload = JSON.parse(Buffer.from(encodedPayload, "base64url").toString()) as TokenPayload;

    // 만료 확인
    const now = Math.floor(Date.now() / 1000);
    if (payload.exp < now) {
      return null;
    }

    return payload;
  } catch {
    return null;
  }
}

/**
 * 쿠키 파싱
 */
export function parseCookies(req: IncomingMessage): Record<string, string> {
  const cookieHeader = req.headers.cookie;
  if (!cookieHeader) {
    return {};
  }

  const cookies: Record<string, string> = {};
  const pairs = cookieHeader.split(";");

  for (const pair of pairs) {
    const [key, value] = pair.trim().split("=");
    if (key && value !== undefined) {
      cookies[key] = decodeURIComponent(value);
    }
  }

  return cookies;
}

/**
 * 쿠키 설정
 */
export function setCookie(
  res: ServerResponse,
  name: string,
  value: string,
  options: Partial<CookieOptions> = {},
): void {
  const defaults: CookieOptions = {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "strict",
    maxAge: 3600, // 1시간
    path: "/",
  };

  const opts = { ...defaults, ...options };
  const secureFlag = opts.secure ? "; Secure" : "";
  const sameSiteFlag = `; SameSite=${opts.sameSite}`;
  const httpOnlyFlag = opts.httpOnly ? "; HttpOnly" : "";
  const maxAgeFlag = `; Max-Age=${opts.maxAge}`;
  const pathFlag = `; Path=${opts.path}`;

  const cookieValue = `${name}=${encodeURIComponent(value)}${httpOnlyFlag}${secureFlag}${sameSiteFlag}${maxAgeFlag}${pathFlag}`;

  const existingCookies = res.getHeader("Set-Cookie") as string[] | string | undefined;
  if (Array.isArray(existingCookies)) {
    res.setHeader("Set-Cookie", [...existingCookies, cookieValue]);
  } else if (existingCookies) {
    res.setHeader("Set-Cookie", [existingCookies, cookieValue]);
  } else {
    res.setHeader("Set-Cookie", cookieValue);
  }
}

/**
 * 쿠키 삭제
 */
export function clearCookie(res: ServerResponse, name: string, path = "/"): void {
  const cookieValue = `${name}=; HttpOnly; Path=${path}; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT`;

  const existingCookies = res.getHeader("Set-Cookie") as string[] | string | undefined;
  if (Array.isArray(existingCookies)) {
    res.setHeader("Set-Cookie", [...existingCookies, cookieValue]);
  } else if (existingCookies) {
    res.setHeader("Set-Cookie", [existingCookies, cookieValue]);
  } else {
    res.setHeader("Set-Cookie", cookieValue);
  }
}

/**
 * 액세스 토큰 및 리프레시 토큰 발급
 */
export function issueTokens(
  res: ServerResponse,
  userId: string,
  sessionId: string,
): { accessToken: string; refreshToken: string } {
  // 액세스 토큰: 15분
  const accessToken = generateToken(
    { userId, sessionId, type: "access" },
    15 * 60, // 15분
  );

  // 리프레시 토큰: 7일
  const refreshToken = generateToken(
    { userId, sessionId, type: "refresh" },
    7 * 24 * 60 * 60, // 7일
  );

  // httpOnly 쿠키로 설정
  setCookie(res, "access_token", accessToken, {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "strict",
    maxAge: 15 * 60, // 15분
    path: "/",
  });

  setCookie(res, "refresh_token", refreshToken, {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "strict",
    maxAge: 7 * 24 * 60 * 60, // 7일
    path: "/api/auth/refresh", // 리프레시 엔드포인트에서만 사용
  });

  return { accessToken, refreshToken };
}

/**
 * 쿠키에서 토큰 검증 및 추출
 */
export function authenticateFromCookies(req: IncomingMessage): {
  valid: boolean;
  payload?: TokenPayload;
  error?: string;
} {
  const cookies = parseCookies(req);
  const accessToken = cookies["access_token"];

  if (!accessToken) {
    return { valid: false, error: "access_token_missing" };
  }

  const payload = verifyToken(accessToken);
  if (!payload) {
    return { valid: false, error: "invalid_or_expired_token" };
  }

  if (payload.type !== "access") {
    return { valid: false, error: "wrong_token_type" };
  }

  return { valid: true, payload };
}

/**
 * 리프레시 토큰으로 새 액세스 토큰 발급
 */
export function refreshAccessToken(
  req: IncomingMessage,
  res: ServerResponse,
): { success: boolean; error?: string } {
  const cookies = parseCookies(req);
  const refreshToken = cookies["refresh_token"];

  if (!refreshToken) {
    return { success: false, error: "refresh_token_missing" };
  }

  const payload = verifyToken(refreshToken);
  if (!payload) {
    return { success: false, error: "invalid_or_expired_refresh_token" };
  }

  if (payload.type !== "refresh") {
    return { success: false, error: "wrong_token_type" };
  }

  // 새 토큰 발급
  issueTokens(res, payload.userId, payload.sessionId);

  return { success: true };
}

/**
 * 로그아웃 (쿠키 삭제)
 */
export function logout(res: ServerResponse): void {
  clearCookie(res, "access_token", "/");
  clearCookie(res, "refresh_token", "/api/auth/refresh");
}

/**
 * Content Security Policy 헤더 설정
 */
export function setSecurityHeaders(res: ServerResponse): void {
  // CSP: XSS 방지
  res.setHeader(
    "Content-Security-Policy",
    "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; connect-src 'self' ws: wss:;",
  );

  // XSS 필터 활성화 (레거시 브라우저)
  res.setHeader("X-XSS-Protection", "1; mode=block");

  // 클릭재킹 방지
  res.setHeader("X-Frame-Options", "DENY");

  // MIME 타입 스니핑 방지
  res.setHeader("X-Content-Type-Options", "nosniff");

  // Referrer 정책
  res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
}
