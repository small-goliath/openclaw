/**
 * httpOnly 쿠키 기반 인증 관리 (서버 측)
 * XSS 공격으로부터 토큰을 보호하기 위해 httpOnly 쿠키 사용
 */

import type { IncomingMessage, ServerResponse } from "node:http";
import crypto from "node:crypto";
import { safeEqualSecret } from "../security/secret-equal.js";
import { logSecurityEvent } from "../security/siem-logger.js";

/**
 * 활성 세션 추적 (세션 고정 방어용)
 * 실제 구현에서는 Redis나 데이터베이스 사용 권장
 */
const activeSessions = new Map<string, { userId: string; createdAt: number }>();

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
 * 개발 환경에서도 랜덤 키를 생성하여 보안 취약점 방지
 */
function getJwtSecret(): string {
  const secret = process.env.OPENCLAW_JWT_SECRET;
  if (!secret) {
    // 프로덕션 환경에서는 필수 환경 변수 검증 강화
    if (process.env.NODE_ENV === "production") {
      throw new Error("OPENCLAW_JWT_SECRET environment variable is required in production");
    }
    // 개발 환경에서도 랜덤 키 생성 (고정된 키 사용 방지)
    // 프로세스 재시작 시 새로운 키가 생성됨
    return crypto.randomBytes(32).toString("hex");
  }

  // 키 길이 검증 (최소 32바이트 = 256비트)
  if (secret.length < 32) {
    throw new Error("OPENCLAW_JWT_SECRET must be at least 32 characters for security");
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
 * 세션 고정 방어를 위해 세션 유효성도 검증
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

    // 세션 유효성 확인 (세션 고정 방어)
    if (!isSessionValid(payload.sessionId)) {
      logSecurityEvent({
        type: "session_validation_failed",
        sessionId: payload.sessionId,
        userId: payload.userId,
        reason: "session_invalidated_or_expired",
        timestamp: Date.now(),
      });
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
 * 세션 무효화 (로그아웃 또는 세션 고정 방어용)
 */
export async function invalidateSession(sessionId: string): Promise<void> {
  const session = activeSessions.get(sessionId);
  if (session) {
    // 세션 무효화 로깅
    await logSecurityEvent({
      type: "session_invalidated",
      sessionId,
      userId: session.userId,
      reason: "session_rotation",
      timestamp: Date.now(),
    });
    activeSessions.delete(sessionId);
  }
}

/**
 * 세션 회전 (세션 고정 방어)
 * 로그인 성공 시 새 세션 ID를 생성하고 기존 세션을 무효화
 */
export async function rotateSession(
  res: ServerResponse,
  oldSessionId: string | null,
  userId: string,
): Promise<{ accessToken: string; refreshToken: string; newSessionId: string }> {
  // 새 세션 ID 생성
  const newSessionId = crypto.randomUUID();

  // 기존 세션 무효화
  if (oldSessionId) {
    await invalidateSession(oldSessionId);
  }

  // 새 세션 등록
  activeSessions.set(newSessionId, {
    userId,
    createdAt: Date.now(),
  });

  // 새 토큰 발급
  const tokens = issueTokens(res, userId, newSessionId);

  // 세션 생성 로깅
  await logSecurityEvent({
    type: "session_created",
    sessionId: newSessionId,
    userId,
    rotatedFrom: oldSessionId,
    timestamp: Date.now(),
  });

  return {
    ...tokens,
    newSessionId,
  };
}

/**
 * 세션 유효성 확인
 */
export function isSessionValid(sessionId: string): boolean {
  return activeSessions.has(sessionId);
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
