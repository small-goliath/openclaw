/**
 * Security Headers Module
 *
 * HTTP 응답에 권장되는 보안 헤더를 적용합니다.
 * OWASP 보안 가이드라인 및 securityheaders.com 권장사항을 따릅니다.
 *
 * @module security/security-headers
 */

import type { Request, Response, NextFunction } from "express";
import type { ServerResponse } from "node:http";

/**
 * 보안 헤더 설정 옵션
 */
export interface SecurityHeadersOptions {
  /** HTTPS 사용 여부 (HSTS 헤더 적용 결정) */
  secure?: boolean;
  /** CSP 정책 커스터마이징 */
  contentSecurityPolicy?: string;
  /** Permissions-Policy 커스터마이징 */
  permissionsPolicy?: string;
}

/**
 * 기본 보안 헤더 값
 */
const DEFAULT_SECURITY_HEADERS = {
  // MIME 스니핑 방지
  "X-Content-Type-Options": "nosniff",

  // 클릭재킹 방지
  "X-Frame-Options": "DENY",

  // XSS 필터 활성화
  "X-XSS-Protection": "1; mode=block",

  // Referrer 정책: 크로스 오리진 시 origin만 전송
  "Referrer-Policy": "strict-origin-when-cross-origin",

  // 기본 CSP: 자기 자신만 허용
  "Content-Security-Policy":
    "default-src 'self'; " +
    "script-src 'self' 'unsafe-inline'; " +
    "style-src 'self' 'unsafe-inline'; " +
    "img-src 'self' data: https:; " +
    "connect-src 'self' ws: wss:; " +
    "font-src 'self'; " +
    "object-src 'none'; " +
    "frame-ancestors 'none'; " +
    "base-uri 'self'; " +
    "form-action 'self';",

  // 기능 권한 제한
  "Permissions-Policy":
    "camera=(), " +
    "microphone=(), " +
    "geolocation=(), " +
    "payment=(), " +
    "usb=(), " +
    "magnetometer=(), " +
    "gyroscope=(), " +
    "accelerometer=(), " +
    "ambient-light-sensor=(), " +
    "autoplay=(), " +
    "battery=(), " +
    "display-capture=(), " +
    "document-domain=(), " +
    "encrypted-media=(), " +
    "fullscreen=(), " +
    "gamepad=(), " +
    "hid=(), " +
    "idle-detection=(), " +
    "local-fonts=(), " +
    "midi=(), " +
    "navigation-override=(), " +
    "picture-in-picture=(), " +
    "publickey-credentials-create=(), " +
    "publickey-credentials-get=(), " +
    "screen-wake-lock=(), " +
    "serial=(), " +
    "speaker-selection=(), " +
    "storage-access=(), " +
    "web-share=(), " +
    "xr-spatial-tracking=()",
};

/**
 * HSTS (HTTP Strict Transport Security) 헤더 값
 */
const HSTS_HEADER = "Strict-Transport-Security";
const HSTS_VALUE = "max-age=31536000; includeSubDomains; preload";

/**
 * 보안 헤더를 ServerResponse에 적용합니다.
 *
 * @param res - Node.js ServerResponse 객체
 * @param options - 보안 헤더 옵션
 *
 * @example
 * ```typescript
 * import { applySecurityHeaders } from "./security-headers.js";
 *
 * const server = createServer((req, res) => {
 *   applySecurityHeaders(res, { secure: true });
 *   res.end("Hello World");
 * });
 * ```
 */
export function applySecurityHeaders(
  res: ServerResponse,
  options: SecurityHeadersOptions = {},
): void {
  const { secure = false, contentSecurityPolicy, permissionsPolicy } = options;

  // 기본 보안 헤더 설정
  for (const [header, value] of Object.entries(DEFAULT_SECURITY_HEADERS)) {
    // CSP와 Permissions-Policy는 커스터마이징 가능
    if (header === "Content-Security-Policy" && contentSecurityPolicy) {
      res.setHeader(header, contentSecurityPolicy);
    } else if (header === "Permissions-Policy" && permissionsPolicy) {
      res.setHeader(header, permissionsPolicy);
    } else {
      res.setHeader(header, value);
    }
  }

  // HTTPS 사용시 HSTS 헤더 추가
  if (secure) {
    res.setHeader(HSTS_HEADER, HSTS_VALUE);
  }
}

/**
 * 보안 헤더 객체를 반환합니다.
 * 테스트나 로깅에 유용합니다.
 *
 * @param options - 보안 헤더 옵션
 * @returns 보안 헤더 객체
 *
 * @example
 * ```typescript
 * const headers = getSecurityHeaders({ secure: true });
 * console.log(headers);
 * ```
 */
export function getSecurityHeaders(options: SecurityHeadersOptions = {}): Record<string, string> {
  const { secure = false, contentSecurityPolicy, permissionsPolicy } = options;

  const headers: Record<string, string> = {};

  for (const [header, value] of Object.entries(DEFAULT_SECURITY_HEADERS)) {
    if (header === "Content-Security-Policy" && contentSecurityPolicy) {
      headers[header] = contentSecurityPolicy;
    } else if (header === "Permissions-Policy" && permissionsPolicy) {
      headers[header] = permissionsPolicy;
    } else {
      headers[header] = value;
    }
  }

  if (secure) {
    headers[HSTS_HEADER] = HSTS_VALUE;
  }

  return headers;
}

/**
 * Express 미들웨어로 보안 헤더를 적용합니다.
 *
 * @param options - 보안 헤더 옵션
 * @returns Express 미들웨어 함수
 *
 * @example
 * ```typescript
 * import express from "express";
 * import { securityHeadersMiddleware } from "./security-headers.js";
 *
 * const app = express();
 * app.use(securityHeadersMiddleware({ secure: true }));
 * ```
 */
export function securityHeadersMiddleware(
  options: SecurityHeadersOptions = {},
): (req: Request, res: Response, next: NextFunction) => void {
  return (req: Request, res: Response, next: NextFunction) => {
    applySecurityHeaders(res as unknown as ServerResponse, options);
    next();
  };
}
